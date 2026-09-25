package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"middleware/pkg/modules"
	"middleware/pkg/storage"
	"middleware/pkg/web"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type DomainRequest struct {
	Domain string `json:"domain" binding:"required"`
}

type CustomURLRequest struct {
	ID   string `json:"id" binding:"required"`
	Name string `json:"name" binding:"required"`
	URL  string `json:"url" binding:"required"`
}

type ToggleRequest struct {
	Enable bool `json:"enable"`
}

type IPBlocklistRequest struct {
	Address string `json:"address" binding:"required"`
}

type ResolverRequest struct {
	Preset  string `json:"preset"`
	Address string `json:"address"`
}

// ReolverPreset is a selectable secure forward DNS resolver
type ResolverPreset struct {
	ID      string `json: "id"`
	Name    string `json: "name"`
	Address string `json: "address"`
	URL     string `json: "url"`
	Note    string `json: "note"`
}

// ReolverPreset is the picker list for the dashboard
var ResolverPresets = []ResolverPreset{
	{ID: "cloudflare", Name: "Cloudflare", Address: "1.1.1.1:53", URL: "https://developers.cloudflare.com/1.1.1.1/", Note: "Privacy-first, very fast, wide anycast."},
	{ID: "cloudflare_family", Name: "Cloudflare (Family)", Address: "1.1.1.3:53", URL: "https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families", Note: "Blocks malware and adult content."},
	{ID: "quad9", Name: "Quad9", Address: "9.9.9.9:53", URL: "https://quad9.net/", Note: "Blocks malware/phishing, Swiss, minimal data collected."},
	{ID: "quad9_nofilter", Name: "Quad9 (no filtering)", Address: "9.9.9.10:53", URL: "https://quad9.net/", Note: "Secure but unfiltered."},
	{ID: "nextdns", Name: "NextDNS", Address: "45.90.28.0:53", URL: "https://nextdns.io/", Note: "Uses your NextDNS profile automatically from this IP."},
	{ID: "adguard", Name: "AdGuard DNS", Address: "94.140.14.14:53", URL: "https://adguard-dns.io/", Note: "Blocks ads, trackers, and phishing."},
	{ID: "google", Name: "Google Public DNS", Address: "8.8.8.8:53", URL: "https://dns.google/", Note: "Standard, widely reachable."},
	{ID: "opendns", Name: "Cisco OpenDNS", Address: "208.67.222.222:53", URL: "https://www.opendns.com/", Note: "With phishing protection."},
}

// resolverPreset returns the preset with the given ID
func resolverPreset(id string) (*ResolverPreset, bool) {
	for _, p := range ResolverPresets {
		if p.ID == id {
			return p, true
		}
	}
	return &ResolverPreset{}, false
}

// UpstreamSwitcher changes the DNS Server's forward resolver at runtime
type UpstreamSwitcher interface {
	SetUpstream(raw string) (string, error)
}

// ModeSwitcher toggles the pipeline between enforce and monitor
type ModeSwitcher interface {
	SetMonitor(on bool)
	Monitor() bool
}

type Server struct {
	db               *storage.Database
	hub              *WSHub
	blocklist        *modules.DynamicBlocklistModule
	blocklistManager *modules.BlocklistManagerModule
	allowlist        *modules.AllowlistModule
	ipBlocklist      *modules.IPBlocklistModule
	resolverSwitcher UpstreamSwitcher
	modeSwitcher     ModeSwitcher
	resolverAddr     string
	router           *gin.Engine
	httpSrv          *http.Server
	addr             string
	authToken        string
	dashboard        []byte
}

func (s *Server) Start() error {
	fmt.Printf("[API] Dashboard Server listening on http://%s\n", s.addr)
	s.httpSrv = &http.Server{Addr: s.addr, Handler: s.router}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully drains on runtime requests and stops the HTTP listener
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

func NewServer(addr string, db *storage.Database, hub *WSHub) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	s := &Server{
		db:               db,
		hub:              hub,
		blocklist:        blocklist,
		blocklistManager: manager,
		router:           router,
		addr:             addr,
		authToken:        authToken,
		dashboard:        web.DashboardHTML(authToken),
	}

	s.setupRoutes()
	return s
}

// hostAllowList rejects requests whose Host Header is not a loopback hostname
func hostAllowList(c *gin.Context) {
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		c.Next()
	default:
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "bad host"})
	}
}

// authRequired demands a valid bearer token on every /api/v1 request
func (s *Server) authRequired(c *gin.Context) {
	if s.authToken == "" {
		c.Next()
		return
	}
	provided := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if subtle.ConstantTimeCompare([]byte(provided), []byte(s.authToken)) != 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Next()
}

// SetIPBlocklist installs the runtime malicious IP matcher for API
func (s *Server) SetIPBlocklist(m *modules.IPBlocklistModule) {
	s.ipBlocklist = m
}

// SetUpstreamSwitcher wires the DNS server so /resolver can switch
func (s *Server) SetUpstreamSwitcher(sw UpstreamSwitcher) {
	s.resolverSwitcher = sw
}

// SetMonitorSwitcher wires the pipeline so /mode can toggle enforce vs monitor mode
func (s *Server) SetMonitorSwitcher(m ModeSwitcher) {
	s.modeSwitcher = m
}

// SetAllowlist wires the allowlist module so /allowlist can manage entries at runtime
func (s *Server) SetAllowlist(m *modules.AllowlistModule) {
	s.allowlist = m
}

// SetCurrentUpstream records the resolver address currently in use
func (s *Server) SetCurrentUpstream(addr string) {
	s.resolverAddr = addr
}

func (s *Server) handleSummary(c *gin.Context) {
	summary, err := s.db.GetSummary()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load summary"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

func (s *Server) handleGetBlocklist(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"blocked_domains": s.blocklist.ListDomains()})
}

func (s *Server) handleAddBlocklist(c *gin.Context) {
	var req DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}

	s.blocklist.AddDomain(req.Domain)
	c.JSON(http.StatusOK, gin.H{"message": "Domain added to blocklist", "domain": req.Domain})
}

func (s *Server) handleRemoveBlocklist(c *gin.Context) {
	var req DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}

	s.blocklist.RemoveDomain(req.Domain)
	c.JSON(http.StatusOK, gin.H{"message": "Domain removed from blocklist", "domain": req.Domain})
}

func (s *Server) handleGetAllowlist(c *gin.Context) {
	if s.allowlist == nil {
		c.JSON(http.StatusOK, gin.H{"allowlisted_domains": []string{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"allowlisted_domains": s.allowlist.ListDomains()})
}

func (s *Server) handleAddAllowlist(c *gin.Context) {
	var req DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}
	if s.allowlist == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "allowlist unavailable"})
		return
	}
	s.allowlist.AddDomain(req.Domain)
	c.JSON(http.StatusOK, gin.H{"message": "domain allowlisted", "domain": req.Domain})
}

func (s *Server) handleRemoveAllowlist(c *gin.Context) {
	var req DomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}
	if s.allowlist == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "allowlist unavailable"})
		return
	}
	s.allowlist.RemoveDomain(req.Domain)
	c.JSON(http.StatusOK, gin.H{"message": "domain removed from allowlist", "domain": req.Domain})
}

// handleGetMode reports the pipline enforcement mode
func (s *Server) handleGetMode(c *gin.Context) {
	mode := "enforce"
	if s.modeSwitcher != nil && s.modeSwitcher.Monitor() {
		mode = "monitor"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

// handleSetModes toggles enforce/monitor at runtime and persists the choice
func (s *Server) handleSetMode(c *gin.Context) {
	var req struct {
		Mode string `json:"mode" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}
	if s.modeSwitcher == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "mode switching unavailable"})
		return
	}
	switch req.Mode {
	case "enforce":
		s.modeSwitcher.SetMonitor(false)
	case "monitor":
		s.modeSwitcher.SetMonitor(true)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'enforce' or 'monitor'"})
		return
	}
	if err := s.db.SetSetting("mode", req.Mode); err != nil {
		s.modeSwitcher.SetMonitor(false)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist mode"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "pipeline mode updated", "mode": req.Mode})
}

func (s *Server) handleGetIPBlocklist(c *gin.Context) {
	if s.ipBlocklist == nil {
		c.JSON(http.StatusOK, gin.H{"blocked_ips": []string{}, "count": 0, "overflow": 0})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"blocked_ips": s.ipBlocklist.List(),
		"count":       s.ipBlocklist.Count(),
		"overflow":    s.ipBlocklist.Overflow(),
	})
}

func (s *Server) handleAddIP(c *gin.Context) {
	var req IPBlocklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}
	if s.ipBlocklist == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IP blocklist unavailable"})
		return
	}
	if err := s.ipBlocklist.Add(req.Address); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP address or CIDR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "IP address blocked", "address": req.Address})
}

func (s *Server) handleRemoveIP(c *gin.Context) {
	var req IPBlocklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}
	if s.ipBlocklist == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IP blocklist unavailable"})
		return
	}
	if err := s.ipBlocklist.Remove(req.Address); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP address or CIDR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "IP address unblocked", "address": req.Address})
}

// handleLogs serves the persisten traffic log, newest first
func (s *Server) handleLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	action := c.Query("action")

	var filter string
	switch action {
	case "", "all":
		filter = ""
	case "blocked", "BLOCK", "Blocked":
		filter = "BLOCK"
	case "allowed", "ALLOW", "Allowed":
		filter = "ALLOW"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action filter"})
		return
	}

	events, err := s.db.QueryLogs(limit, offset, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load logs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "count": len(events)})
}

// handleClearLogs wipes the persistent traffic log
func (s *Server) handleClearLogs(c *gin.Context) {
	deleted, err := s.db.EraseLogs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear logs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "traffic logs cleared", "deleted": deleted})
}

// handleRecentActivity serves the in-memory live-activity backfill from the WebSocket hub
func (s *Server) handleRecentActivity(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	events, dropped := s.hub.Recent(limit)
	c.JSON(http.StatusOK, gin.H{"events": events, "dropped": dropped})
}

// handleGetResolver reports the active forward resolver and the preset picker
func (s *Server) handleGetResolver(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"upstream": s.resolverAddr,
		"presets":  ResolverPresets,
	})
}

// handleSetResolver switches the forward resolver
func (s *Server) handleSetResolver(c *gin.Context) {
	var req ResolverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
		return
	}
	if s.resolverSwitcher == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "resolver switching unavailable"})
		return
	}

	addr := req.Address
	switch {
	case req.Preset == "" && req.Address == "":
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide a preset or an upstream address"})
		return
	case req.Preset != "" && req.Address != "":
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide either a preset or an address, not both"})
		return
	}
	if req.Preset != "" {
		p, ok := resolverPreset(req.Preset)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown resolver preset"})
			return
		}
		addr = p.Address
	}

	normalized, err := s.resolverSwitcher.SetUpstream(addr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upstream resolver"})
		return
	}
	if err := s.db.SetSetting("upstream_dns", normalized); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist resolver choice"})
		return
	}
	s.resolverAddr = normalized
	c.JSON(http.StatusOK, gin.H{"message": "Forward resolver updated", "upstream": normalized})
}

func (s *Server) setupRoutes() {
	// For Web UI
	s.router.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", s.dashboard)
	})

	api := s.router.Group("/api/v1", hostAllowList)
	{
		// /ws authenticates itself via the Sec-WebSocket-Protocol subprotocol (browsers cannot set Authorization headers); everything else requires a bearer token.
		api.GET("/ws", func(c *gin.Context) {
			s.hub.HandleWS(c.Writer, c.Request)
		})

		authed := api.Group("")
		authed.Use(s.authRequired)
		{
			authed.GET("/summary", s.handleSummary)
			authed.GET("/summary/:id", s.handleSummary)

			// Blocklist Management Routes
			authed.GET("/blocklist", s.handleGetBlocklist)
			authed.POST("/blocklist", s.handleAddBlocklist)
			authed.DELETE("/blocklist", s.handleRemoveBlocklist)

			// Allowlist
			authed.GET("/allowlist", s.handleGetAllowlist)
			authed.POST("/allowlist", s.handleAddAllowlist)
			authed.DELETE("/allowlist", s.handleRemoveAllowlist)

			// Enforce vs monitor (observe-only) pipeline mode
			authed.GET("/mode", s.handleGetMode)
			authed.POST("/mode", s.handleSetMode)

			// Runtime IP/CIDR blocklist (direct-IP attack blocking)
			authed.GET("/ipblocklist", s.handleGetIPBlocklist)
			authed.POST("/ipblocklist", s.handleAddIP)
			authed.DELETE("/ipblocklist", s.handleRemoveIP)

			// Persistent traffic log (SQLite) and live-activity backfill (WS hub)
			authed.GET("/logs", s.handleLogs)
			authed.DELETE("/logs", s.handleClearLogs)
			authed.GET("/activity/recent", s.handleRecentActivity)

			// Forward-DNS resolver selection
			authed.GET("/resolver", s.handleGetResolver)
			authed.POST("/resolver", s.handleSetResolver)

			// Bulk Refresh to trigger blocklist re-indexing (background)
			authed.POST("/sources/refresh", func(c *gin.Context) {
				go s.blocklistManager.RefreshAllEnabled()
				c.JSON(http.StatusOK, gin.H{"message": "Background refresh of all enabled blocklists"})
			})

			// Telemetry-only refresh: re-imports enabled file-type
			authed.POST("/sources/telemetry-refresh", func(c *gin.Context) {
				go s.blocklistManager.RefreshTelemetry()
				c.JSON(http.StatusOK, gin.H{"message": "Background refresh of enabled telemetry sources"})
			})

			// Blocklist Manager Endpoints
			authed.GET("/sources", func(c *gin.Context) {
				c.JSON(http.StatusOK, s.blocklistManager.ListSources())
			})

			authed.GET("/categories", func(c *gin.Context) {
				c.JSON(http.StatusOK, s.blocklistManager.ListCategories())
			})

			authed.POST("/categories/toggle/:name", func(c *gin.Context) {
				name, err := url.PathUnescape(c.Param("name"))
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid category name"})
					return
				}
				var req ToggleRequest
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
					return
				}
				if err := s.blocklistManager.ToggleCategory(name, req.Enable); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update category"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "Category updated successfully"})
			})

			authed.POST("/sources/toggle/:id", func(c *gin.Context) {
				id := c.Param("id")
				var req ToggleRequest
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
					return
				}
				if err := s.blocklistManager.ToggleSource(id, req.Enable); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update source"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "URL updated successfully"})
			})

			authed.POST("/sources/custom-url", func(c *gin.Context) {
				var req CustomURLRequest
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload format"})
					return
				}
				if err := s.blocklistManager.AddCustomURL(req.ID, req.Name, req.URL); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid custom URL list"})
					return
				}
				c.JSON(http.StatusCreated, gin.H{"message": "Custom URL list added successfully"})
			})

			authed.POST("/sources/upload", func(c *gin.Context) {
				file, err := c.FormFile("file")
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "file upload required"})
					return
				}
				listID := c.PostForm("id")
				listName := c.PostForm("name")

				if err := os.MkdirAll("./uploads", 0755); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upload directory"})
					return
				}

				safeFilename := filepath.Base(filepath.Clean(file.Filename))
				if safeFilename == "." || safeFilename == "/" || safeFilename == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
					return
				}

				filePath := filepath.Join("./uploads", safeFilename)
				if err := c.SaveUploadedFile(file, filePath); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save blocklist file"})
					return
				}

				if err := s.blocklistManager.ImportFile(listID, listName, filePath); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to import blocklist file"})
					return
				}
				c.JSON(http.StatusCreated, gin.H{"message": "blocklist file imported successfully"})
			})
		}
	}
}
