package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"middleware/pkg/pipeline"
	"middleware/pkg/storage"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const upstreamTimeout = 2 * time.Second

type Server struct {
	engine    *pipeline.Engine
	udpServer *dns.Server
	tcpServer *dns.Server
	upstream  atomic.Pointer[string]
	failovers atomic.Pointer[[]string]
	cache     *dnsCache
	db        *storage.Database
	events    storage.EventSink
	ipMatcher IPChecker
	matcherMu sync.RWMutex
	sampler   *storage.Sampler
}

// IPChecker reports whether a destination IP is inside the runtime
type IPChecker interface {
	ContainsIP(ip net.IP) bool
}

// SetIPMatcher installs the runtime IP matcher pages resolve to blocked IP
func (s *Server) SetIPMatcher(m IPChecker) {
	s.matcherMu.Lock()
	s.ipMatcher = m
	s.matcherMu.Unlock()
}

// SetSmapler installs the allowed-traffic sampler
func (s *Server) SetSampler(sampler *storage.Sampler) {
	s.sampler = sampler
}

// NormalizeUpstream canonicalizes a forward resolver address
func NormalizeUpstream(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", fmt.Errorf("upstream resolver is empty")
	}
	scheme := ""
	if rest, ok := strings.CutPrefix(addr, tlsScheme); ok {
		scheme = tlsScheme
		addr = rest
	}
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		return "", fmt.Errorf("upstream %q has no host", raw)
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return "", fmt.Errorf("upstream %q is a loopback address (would loop)", raw)
	}
	if strings.EqualFold(host, "localhost") {
		return "", fmt.Errorf("upstream %q is the loopback hostname (would loop)", raw)
	}
	if port == "" {
		port = "53"
		if scheme == tlsScheme {
			port = defaultTLSPort
		}
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("upstream %q has invalid port %q", raw, port)
	}
	canonical := net.JoinHostPort(host, port)
	if scheme == tlsScheme {
		canonical = tlsScheme + canonical
	}
	return canonical, nil
}

// tlsScheme marks a DNS-over-TLS (DoT) upstream.
const tlsScheme = "tls://"

const defaultTLSPort = "853"

func NewServer(addr string, upstream string, engine *pipeline.Engine, db *storage.Database, events storage.EventSink) *Server {
	s := &Server{
		engine: engine,
		db:     db,
		events: events,
		cache:  newDNSCache(DefaultCacheEntries),
	}
	s.upstream.Store(&upstream)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	s.udpServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}
	s.tcpServer = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}
	return s
}

// SetUpStream switches the forward resolver at runtime
func (s *Server) SetUpstream(raw string) (string, error) {
	addr, err := NormalizeUpstream(raw)
	if err != nil {
		return "", err
	}
	s.upstream.Store(&addr)
	return addr, nil
}

// CurrentUpstream returns the active forward-resolver address.
func (s *Server) CurrentUpstream() string {
	if p := s.upstream.Load(); p != nil {
		return *p
	}
	return ""
}

// SetFailovers installs the ordered list of fallback resolvers
func (s *Server) SetFailovers(raw []string) error {
	var out []string
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		n, err := NormalizeUpstream(r)
		if err != nil {
			return err
		}
		out = append(out, n)
	}
	s.failovers.Store(&out)
	return nil
}

// failoverList returns the currently configured failover resolvers.
func (s *Server) failoverList() []string {
	if p := s.failovers.Load(); p != nil {
		return *p
	}
	return nil
}

// setFailoversRaw stores failovers, bypassing loopback guard
func (s *Server) setFailoversRaw(raw []string) {
	s.failovers.Store(&raw)
}

// upstreamOrder returns the privacy upstream followed by failovers
func (s *Server) upstreamOrder() []string {
	primary := s.CurrentUpstream()
	order := []string{primary}
	for _, u := range s.failoverList() {
		if u != "" && u != primary {
			order = append(order, u)
		}
	}
	return order
}

func (s *Server) Start() error {
	if s.udpServer == nil || s.tcpServer == nil {
		return errors.New("dns server not constructed")
	}
	slog.Info("DNS resolver listening", "addr", s.udpServer.Addr)
	servers := []*dns.Server{s.udpServer, s.tcpServer}
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		serve := srv
		go func() {
			errs <- serve.ListenAndServe()
		}()
	}
	if err := <-errs; err != nil {
		// A failed bind on one listener must not leave a half-open resolver:
		// stop the sibling and report.
		shutdownErrs := []error{err}
		for _, srv := range servers {
			if shutdownErr := srv.Shutdown(); shutdownErr != nil {
				shutdownErrs = append(shutdownErrs, fmt.Errorf("shutdown DNS listener %s: %w", srv.Addr, shutdownErr))
			}
		}
		return errors.Join(shutdownErrs...)
	}
	return nil
}

// Shutdown stops both listeners gracefully (used on daemon exit).
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	for _, srv := range []*dns.Server{s.udpServer, s.tcpServer} {
		if srv == nil {
			continue
		}
		if err := srv.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	// KI-24: normalize and validate the wire name before it is logged, stored,
	// or passed to the policy pipeline. Hostile names get SERVFAIL and are not
	// recorded.

	domain := pipeline.SanitizeDomain(q.Name)
	if domain == "" {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	clientIPStr, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	clientIP := net.ParseIP(clientIPStr)

	tctx := pipeline.NewTrafficContext("DNS-REQ", clientIP, domain, q.Qtype)

	s.engine.Process(context.Background(), tctx)

	event := storage.LogEvent{
		Timestamp:   tctx.Timestamp,
		Protocol:    "DNS",
		ClientIP:    clientIPStr,
		Target:      domain,
		Action:      tctx.FinalAction.String(),
		BlockReason: tctx.BlockReason,
		MatchedBy:   tctx.MatchedBy,
	}

	s.record(event)

	// EnforcedAction (KI-13): in monitor mode a blocked decision is observed
	// here but the query is forwarded instead of answered with a block, so
	// nothing is interrupted while the heuristic is evaluated.
	if tctx.EnforcedAction() == pipeline.ActionBlock {
		slog.Info("DNS block", "domain", domain, "reason", tctx.BlockReason, "matched_by", tctx.MatchedBy)
		w.WriteMsg(blockResponse(r, q))
		return
	}

	// KI-17: a bounded, TTL-aware answer cache short-circuits repeat lookups.
	// Cached answers still pass the KI-25 blocked-IP check before they are
	// forwarded to a client.
	if cached := s.cache.get(cacheKey(domain, q.Qtype)); cached != nil {
		out, _ := s.checkResolvedBlock(r, q, domain, clientIPStr, cached)
		slog.Debug("DNS cache hit", "domain", domain)
		w.WriteMsg(out)
		return
	}

	in, err := s.resolve(r)
	if err != nil {
		slog.Warn("DNS resolver failure", "domain", domain, "error", err)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	if ttl := answerTTL(in); ttl > 0 {
		s.cache.put(cacheKey(domain, q.Qtype), in, ttl)
	}

	out, _ := s.checkResolvedBlock(r, q, domain, clientIPStr, in)
	w.WriteMsg(out)
}

// resolve forward q query to the primary upstream, falling back through the configured failover
func (s *Server) resolve(r *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	tried := 0
	for _, u := range s.upstreamOrder() {
		if u == "" {
			continue
		}
		tried++
		in, err := s.exchange(r, u)
		if err == nil {
			return in, nil
		}
		lastErr = err
	}
	if tried == 0 {
		return nil, fmt.Errorf("no upstream configured")
	}
	return nil, fmt.Errorf("all %d upstream(s) failed: %w", tried, lastErr)
}

// exchange performs one query against a single upstream
func (s *Server) exchange(r *dns.Msg, upstream string) (*dns.Msg, error) {
	client := &dns.Client{Timeout: upstreamTimeout}
	addr := upstream
	if rest, ok := strings.CutPrefix(upstream, tlsScheme); ok {
		host, _, err := net.SplitHostPort(rest)
		if err != nil {
			return nil, fmt.Errorf("malformed DoT upstream %q: %w", upstream, err)
		}
		client.Net = "tcp-tls"
		// ServerName keeps certificate verification strict: providers
		// (Cloudflare 1.1.1.1, Quad9 9.9.9.9) publish SANs for their
		// resolver IPs, so the IP literal verifies.
		client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	} else {
		client.Net = "udp"
	}
	in, _, err := client.Exchange(r, addr)
	return in, err
}

// record feeds an event to the persistent log and the live WebSocket hub
func (s *Server) record(e storage.LogEvent) {
	if s.sampler != nil && !s.sampler.ShouldRecord(e.Action) {
		return
	}
	if s.db != nil {
		s.db.Log(e)
	}
	if s.events != nil {
		s.events.Broadcast(e)
	}
}

// checkResolvedBlock checks for blocked IP checks
func (s *Server) checkResolvedBlock(r *dns.Msg, q dns.Question, domain, clientIPStr string, in *dns.Msg) (out *dns.Msg, handled bool) {
	blockedIP := s.blockedAnswerIP(in)
	if blockedIP == "" {
		return in, false
	}
	reason := "resolved IP " + blockedIP + " matched IP blocklist"
	if s.engine != nil && s.engine.Monitor() {
		s.record(storage.LogEvent{
			Timestamp:   time.Now(),
			Protocol:    "DNS",
			ClientIP:    clientIPStr,
			Target:      domain,
			Action:      pipeline.ActionBlock.String(),
			BlockReason: reason + " (monitor)",
			MatchedBy:   "IPBlocklist",
		})
		slog.Info("DNS resolve-to-blocked-IP observed (monitor)", "domain", domain, "ip", blockedIP)
		return in, false
	}
	s.record(storage.LogEvent{
		Timestamp:   time.Now(),
		Protocol:    "DNS",
		ClientIP:    clientIPStr,
		Target:      domain,
		Action:      pipeline.ActionBlock.String(),
		BlockReason: reason,
		MatchedBy:   "IPBlocklist",
	})
	slog.Info("DNS block (blocked-IP)", "domain", domain, "ip", blockedIP)
	return blockResponse(r, q), true
}

// blockResponse builds the synthetic blackhole for refused query
func blockResponse(r *dns.Msg, q dns.Question) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	switch q.Qtype {
	case dns.TypeA:
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 in A 0.0.0.0", q.Name))
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeAAAA:
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 in AAAA ::", q.Name))
		if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	default:
		m.Rcode = dns.RcodeNameError
	}
	return m
}

// blockedAnswerIP returns the first A/AAAA IP in the response
func (s *Server) blockedAnswerIP(in *dns.Msg) string {
	if in == nil {
		return ""
	}
	s.matcherMu.RLock()
	m := s.ipMatcher
	s.matcherMu.RUnlock()
	if m == nil {
		return ""
	}
	for _, rr := range in.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if v != nil && m.ContainsIP(v.A) {
				return v.A.String()
			}
		case *dns.AAAA:
			if v != nil && m.ContainsIP(v.AAAA) {
				return v.AAAA.String()
			}
		}
	}
	return ""
}
