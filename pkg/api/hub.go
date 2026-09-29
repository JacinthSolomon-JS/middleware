package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"middleware/pkg/storage"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

func closeWebSocket(context string, conn *websocket.Conn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("[WS WARNING] failed to close %s: %v", context, err)
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     allowedOrigin,
}

// allowedOrigin only permits sam origin WebSockets upgrades
func allowedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	switch origin {
	case "http://127.0.0.1:8080", "http://localhost:8080",
		"http://127.0.0.1", "http://localhost":
		return true
	}
	return false
}

// Hub timings and bounds
const (
	hubMaxClients      = 50   // concurrent dashboard connections
	hubClientSendQ     = 256  // buffered messages per client
	hubMaxMessageBytes = 4096 // inbound frame size limit
	hubPongWait        = 60 * time.Second
	hubPingPeriod      = (hubPongWait * 9) / 10
	hubWriteWait       = 5 * time.Second
	hubBroadcastQ      = 1000 // global broadcast queue before drop
)

type wsClient struct {
	hub        *WSHub
	conn       *websocket.Conn
	send       chan []byte
	pongWait   time.Duration
	pingPeriod time.Duration
	writeWait  time.Duration
}

type WSHub struct {
	authToken  string
	clients    map[*wsClient]bool
	maxClients int
	broadcast  chan storage.LogEvent
	register   chan *wsClient
	closed     chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex

	// Keep alive
	pongWait   time.Duration
	pingPeriod time.Duration
	writeWait  time.Duration

	// Counted overflow
	broadcastDrops  uint64
	clientMsgDrops  uint64
	rejectedClients uint64

	// Recent holds
	recentMu    sync.Mutex
	recent      []storage.LogEvent
	recentDrops uint64
}

// recentMaxEvents bounds the live activity backfill buffer
const recentMaxEvents = 1000

// NewWSHub builds a hub
func NewWSHub(authToken ...string) *WSHub {
	token := ""
	if len(authToken) > 0 {
		token = authToken[0]
	}
	return &WSHub{
		authToken:  token,
		clients:    make(map[*wsClient]bool),
		maxClients: hubMaxClients,
		broadcast:  make(chan storage.LogEvent, hubBroadcastQ),
		register:   make(chan *wsClient, hubMaxClients),
		closed:     make(chan struct{}),
		pongWait:   hubPongWait,
		pingPeriod: hubPingPeriod,
		writeWait:  hubWriteWait,
	}
}

// SetKeepAlive configures the keep alive parameters
func (h *WSHub) SetKeepAlive(pongWait, writeWait time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if pongWait <= 0 {
		pongWait = hubPongWait
	}
	if writeWait <= 0 {
		writeWait = hubWriteWait
	}
	h.pongWait = pongWait
	h.pingPeriod = (pongWait * 9) / 10
	h.writeWait = writeWait
}

// SetMaxClients overrides the default connection cap
func (h *WSHub) SetMacClients(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n <= 0 {
		n = hubMaxClients
	}
	h.maxClients = n
}

func (h *WSHub) Run() {
	for {
		select {
		case <-h.closed:
			return

		case c := <-h.register:
			h.mu.Lock()
			atCap := len(h.clients) >= h.maxClients
			if !atCap {
				h.clients[c] = true
				c.pongWait = h.pongWait
				c.pingPeriod = h.pingPeriod
				c.writeWait = h.writeWait
			}
			h.mu.Unlock()
			if atCap {
				h.countReject()
				if err := c.conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation,
						"client limit reached"), time.Now().Add(hubWriteWait)); err != nil {
					log.Printf("[WS WARNING] failed to send client-limit close frame: %v", err)
				}
				closeWebSocket("rejected client", c.conn)
				continue
			}
			go c.writePump()
			go c.readPump()

		case event := <-h.broadcast:
			msg, err := json.Marshal(event)
			if err != nil {
				log.Printf("[WS ERROR] failed to encode broadcast event: %v", err)
				continue
			}
			h.mu.Lock()
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					h.clientMsgDrops++
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *WSHub) countReject() {
	h.mu.Lock()
	h.rejectedClients++
	h.mu.Unlock()
}

// unregisterClient removes and closes its socket
func (h *WSHub) unregisterClient(c *wsClient) {
	h.mu.Lock()
	if _, ok := h.clients[c]; !ok {
		h.mu.Unlock()
		return
	}
	delete(h.clients, c)
	h.mu.Unlock()
	closeWebSocket("unregistered client", c.conn)
}

func (h *WSHub) Broadcast(event storage.LogEvent) {
	h.recentMu.Lock()
	h.recent = append(h.recent, event)
	if n := len(h.recent); n > recentMaxEvents {
		drop := n - recentMaxEvents
		h.recent = h.recent[drop:]
		h.recentDrops += uint64(drop)
	}
	h.recentMu.Unlock()

	select {
	case h.broadcast <- event:
	default:
		h.mu.Lock()
		h.broadcastDrops++
		h.mu.Unlock()
	}
}

// Recent returns up to limit of the newest live events
func (h *WSHub) Recent(limit int) ([]storage.LogEvent, uint64) {
	if limit <= 0 || limit > recentMaxEvents {
		limit = recentMaxEvents
	}
	h.recentMu.Lock()
	defer h.recentMu.Unlock()

	events := make([]storage.LogEvent, 0, min(limit, len(h.recent)))
	for i := len(h.recent) - 1; i >= 0 && len(events) < limit; i-- {
		events = append(events, h.recent[i])
	}
	return events, h.recentDrops
}

// Stop terminates the Run goroutine and closes every client connection
func (h *WSHub) Stop() {
	h.closeOnce.Do(func() { close(h.closed) })

	h.mu.Lock()
	clients := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		closeWebSocket("client during hub shutdown", c.conn)
	}
}

// Drops returns the counted overflow counters
func (h *WSHub) Drops() (broadcast, client, rejected uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.broadcastDrops, h.clientMsgDrops, h.rejectedClients
}

func (h *WSHub) HandleWS(w http.ResponseWriter, r *http.Request) {
	u := upgrader
	if h.authToken != "" {
		proto := r.Header.Get("Sec-WebSocket-Protocol")
		if subtle.ConstantTimeCompare([]byte(proto), []byte(h.authToken)) != 1 {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}
		u.Subprotocols = []string{proto}
	}
	conn, err := u.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("\n[WS ERROR] Upgrade failed: %v\n", err)
		return
	}
	c := &wsClient{
		hub:  h,
		conn: conn,
		send: make(chan []byte, hubClientSendQ),
	}
	h.register <- c
}

// writePump drains the clients outbound queue and emits keep alive pings
func (c *wsClient) writePump() {
	ticker := time.NewTicker(c.pingPeriod)
	defer func() {
		ticker.Stop()
		close(c.send)
		c.hub.unregisterClient(c)
	}()

	for {
		select {
		case msg, ok := <-c.send:
			if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeWait)); err != nil {
				log.Printf("[WS WARNING] failed to set client write deadline: %v", err)
				return
			}
			if !ok {
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				log.Printf("[WS WARNING] failed to write client message: %v", err)
				return
			}
		case <-ticker.C:
			if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeWait)); err != nil {
				log.Printf("[WS WARNING] failed to set ping write deadline: %v", err)
				return
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[WS WARNING] failed to write client ping: %v", err)
				return
			}
		}
	}
}

// readPump consumes control frames
func (c *wsClient) readPump() {
	defer func() {
		c.hub.unregisterClient(c)
		closeWebSocket("reader client", c.conn)
	}()

	c.conn.SetReadLimit(hubMaxMessageBytes)
	if err := c.conn.SetReadDeadline(time.Now().Add(c.pongWait)); err != nil {
		log.Printf("[WS WARNING] failed to set client read deadline: %v", err)
		return
	}
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(c.pongWait))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[WS WARNING] client read failed: %v", err)
			}
			return
		}
	}
}
