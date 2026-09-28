package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"middleware/pkg/api"
	"middleware/pkg/dns"
	"middleware/pkg/interceptor"
	"middleware/pkg/modules"
	"middleware/pkg/pipeline"
	"middleware/pkg/storage"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue/v2"
)

func main() {
	// For Clean start up running a standalone subcommand to remove every tagged IPTable rules
	if len(os.Args) > 1 && os.Args[1] == "--cleanup" {
		cleanupIptables()
		fmt.Println("[CLEANUP] Removed all tagged rules. Internet and DNS restored")
	}

	fmt.Println("Starting Gateway Resolver...")

	// Setup Signal Handling & Context for Graceful Shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Database Log before policy modules for persist function
	fmt.Println("\n[STARTED] - DB: Initialized Database")
	db, err := storage.NewDatabase(dbPath(), 10000, 50, 1*time.Second)
	if err != nil {
		log.Fatalf("\n[ERROR] - Database: Failed to connect to database: %v", err)
	}
	defer func(db *storage.Database) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	// Retention for traffic log
	retention := 0 * time.Second
	if v := os.Getenv("LOG_RETENTION"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d <= 0 {
			log.Fatalf("[ERROR] - LOG_RETENTION: Invalid positive duration %q", v)
		} else {
			retention = d
		}
	}

	var maxRows uint64
	if v := os.Getenv("GATEWAY_LOG_MAX_ROWS"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			log.Fatalf("[ERROR] - GATEWAY_LOG_MAX_ROWS is not a valid positive integer: %q", v)
		}
		maxRows = n
	}
	db.SetRetention(retention, maxRows)

	// Starting Database
	db.Start(ctx)

	// Initialize Blocklist Manager
	blocklistMgr, err := modules.NewBlocklistManagerModuleWithStore("configs/blocklists.yaml", db)
	if err != nil {
		log.Fatalf("[ERROR] - BlocklistManager: Failed to initialize blocklist manager: %v", err)
	}

	// Runtime added domains
	dynamicBlocklist := modules.NewDynamicBlocklistModule([]string{
		"malware.com",
		"phishing-site.net",
	}, db)

	ipBlocklist := modules.NewIPBlocklistModule(db)

	// Entropy threshold is a persisted setting (default 4.1).
	entropyThreshold := 4.1
	if v, ok, err := db.GetSetting("entropy_threshold"); err != nil {
		log.Printf("[WARNING] Failed to read entropy_threshold setting: %v", err)
	} else if ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			entropyThreshold = f
		} else {
			log.Printf("[WARNING] Ignoring invalid entropy_threshold %q", v)
		}
	}

	entropyModule := modules.NewEntropyModule(entropyThreshold)
	if v, ok, err := db.GetSetting("entropy_enforce"); err != nil {
		log.Printf("[WARNING] Failed to read entropy_enforce setting: %v", err)
	} else if ok && v == "1" {
		entropyModule.SetLogOnly(false)
		log.Println("[WARNING] DGA heuristic is ENFORCING (entropy_enforce=1): high-entropy names are blocked.")
	}

	// Initialize Pipeline & Engine Setup
	engine := pipeline.NewEngine()
	allowlist := modules.NewAllowlistModule([]string{}, db)
	engine.RegisterModule(allowlist)
	engine.RegisterModule(blocklistMgr)
	engine.RegisterModule(dynamicBlocklist)
	engine.RegisterModule(entropyModule)

	mode, _, _ := db.GetSetting("mode")
	if strings.TrimSpace(mode) == "monitor" {
		engine.SetMonitor(true)
		log.Println("[WARNING] Pipeline is in MONITOR mode: blocked traffic is logged but not interrupted.")
	}

	// API bearer token
	apiToken, err := loadAPIToken()
	if err != nil {
		log.Fatalf("[ERROR] - API: failed to load token: %v", err)
	}

	// WebSocket Hub & API Server
	wsHub := api.NewWSHub(apiToken)
	go wsHub.Run()

	eventSampler := storage.NewSampler(allowSampleN())

	// Initialize Inspector & Handler
	inspector := interceptor.NewPacketInspector(engine)
	handler := interceptor.NewNFQueueHandler(engine, inspector, db, wsHub)
	handler.SetIPBlocklist(ipBlocklist)
	handler.SetSampler(eventSampler)

	apiServer := api.NewServer(apiListenAddr(), apiToken, db, wsHub, dynamicBlocklist, blocklistMgr)
	apiServer.SetIPBlocklist(ipBlocklist)
	apiServer.SetAllowlist(allowlist)
	apiServer.SetMonitorSwitcher(engine)

	// Tag-based iptables cleanup
	iptablesUp := false
	cleanupIptablesOnce := func() {
		if !iptablesUp {
			return
		}
		iptablesUp = false
		cleanupIptables()
	}
	defer cleanupIptablesOnce()
	go func() {
		if err := apiServer.Start(); err != nil {
			cleanupIptablesOnce()
			log.Fatalf("[ERROR] - API: Server failed error: %v", err)
		}
	}()

	// DNS Resolver Server Setup
	upstream := "1.1.1.1:53"
	if v, ok, err := db.GetSetting("upstream_dns"); err != nil {
		log.Printf("[WARNING] Failed to read upstream_dns setting: %v", err)
	} else if ok && strings.TrimSpace(v) != "" {
		if n, err := dns.NormalizeUpstream(v); err == nil {
			upstream = n
		} else {
			log.Printf("[WARNING] Ignoring invalid upstream_dns %q: %v", v, err)
		}
	}
	fmt.Printf("\n[STARTING] - DNS: Local Resolver on UDP+TCP %s\n", dnsListenAddr())
	dnsServer := dns.NewServer(dnsListenAddr(), upstream, engine, db, wsHub)

	dnsServer.SetIPMatcher(ipBlocklist)
	dnsServer.SetSampler(eventSampler)
	go func() {
		if err := dnsServer.Start(); err != nil {

			log.Printf("\n[ERROR] - DNS: Server failed to start: %v", err)
		}
	}()
	apiServer.SetUpstreamSwitcher(dnsServer)
	apiServer.SetCurrentUpstream(upstream)

	// Initialize Shutdown Signal
	sigChain := make(chan os.Signal, 1)
	signal.Notify(sigChain, syscall.SIGINT, syscall.SIGTERM)

	// Configure IPTables Rules
	setupIptables()
	iptablesUp = true

	// NFQUEUE Initialization
	fmt.Println("\nAttempting to connect to NFQUEUE Number 0...")
	config := nfqueue.Config{
		NfQueue:      uint16(nfqueueNum()),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		cleanupIptablesOnce()
		log.Fatalf("Could not open NFQUEUE: %v", err)
	}
	defer func(nf *nfqueue.Nfqueue) {
		err := nf.Close()
		if err != nil {

		}
	}(nf)

	nfHook := func(a nfqueue.Attribute) int {
		return handler.HandlePacket(nf, a)
	}

	errHook := func(err error) int {
		log.Printf("[NFQUEUE ERROR] Background queue worker error: %v", err)
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, nfHook, errHook); err != nil {
		cleanupIptablesOnce()
		log.Fatalf("Failed to register nfqueue: %v", err)
	}

	fmt.Println("Successfully connected to NFQUEUE!")

	// Feed downloads happens in the background
	go blocklistMgr.RefreshAllEnabled()

	// Telemetry/tracking sources (off by default)
	go blocklistMgr.StartTelemetryRefresh(ctx, modules.TelemetryAutoRefreshInterval)

	fmt.Println("\n[ACTIVE] - Process: waiting for packets... (Press Ctrl+C to stop)")

	// Wait for Shutdown Signal
	<-sigChain
	fmt.Println("\nShutting down Gateway...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsHub.Stop()
	if eventSampler.Nth() > 1 && eventSampler.Skipped() > 0 {
		log.Printf("[STATS] ALLOW events sampled out during this run: %d (interval %d)",
			eventSampler.Skipped(), eventSampler.Nth())
	}
	if err := dnsServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[WARNING] DNS server shutdown: %v", err)
	}
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[WARNING] API server shutdown: %v", err)
	}
}

// interceptorProtocol returns the gateway protocol mode
func interceptProtocol() string {
	if p := strings.TrimSpace(os.Getenv("GATEWAY_INTERCEPT_PROTO")); p != "" {
		return p
	}
	return "all"
}

// interceptMaxPackets returns the maximum number of packets to intercept
func interceptMaxPackets() string {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_INTERCEPT_MAX_PACKETS")); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			return v
		}
		log.Printf("[WARNING] Ignoring invalid GATEWAY_INTERCEPT_MAX_PACKETS %q; using default", v)
	}
	return "8"
}

// ipv6Enabled returns whether to install ip6tables rules
func ipv6Enabled() bool {
	return strings.TrimSpace(os.Getenv("GATEWAY_IPV6")) == "1"
}

// apiListenAddr returns the management-plane listener
func apiListenAddr() string {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_API_ADDR")); v != "" {
		if _, _, err := net.SplitHostPort(v); err == nil {
			return v
		}
		log.Printf("[WARNING] Ignoring invalid GATEWAY_API_ADDR %q; using default", v)
	}
	return "127.0.0.1:8080"
}

// dnsListenAddr returns the local resolver listener (UDP+TCP)
func dnsListenAddr() string {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_DNS_ADDR")); v != "" {
		if _, port, err := net.SplitHostPort(v); err == nil && port != "" {
			return v
		}
		log.Printf("[WARNING] Ignoring invalid GATEWAY_DNS_ADDR %q; using default", v)
	}
	return "127.0.0.1:1053"
}

// dnsRedirectPort returns the port half of dnsListenAddr().
func dnsRedirectPort() string {
	_, port, err := net.SplitHostPort(dnsListenAddr())
	if err != nil || port == "" {
		return "1053"
	}
	return port
}

// dbPath returns the SQLite file. GATEWAY_DB_PATH overrides the default
func dbPath() string {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_DB_PATH")); v != "" {
		return v
	}
	return "gateway.db"
}

// nfqueueNum returns the NFQUEUE number for the outbound inspector.
func nfqueueNum() int {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_NFQUEUE_NUM")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
		log.Printf("[WARNING] Ignoring invalid GATEWAY_NFQUEUE_NUM %q; using default", v)
	}
	return 0
}

// allowSampleN returns the allowed-traffic sampling interval
func allowSampleN() int64 {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_LOG_SAMPLE_ALLOW")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
		log.Printf("[WARNING] Ignoring invalid GATEWAY_LOG_SAMPLE_ALLOW %q; recording all", v)
	}
	return 0
}

// flowStartMatches are the conntrack + connbytes matches that gateway interception
func flowStartMatches(maxPackets string) []string {
	return []string{
		"-m", "conntrack", "--ctstate", "NEW,ESTABLISHED",
		"-m", "connbytes", "--connbytes", "0:" + maxPackets,
		"--connbytes-dir", "original", "--connbytes-mode", "packets",
	}
}

// getIptablesRules returns the iptables rules for the given action
func getIptablesRules(action string) [][]string {
	proto := interceptProtocol()
	maxPackets := interceptMaxPackets()

	tagged := func(extra ...string) []string {
		base := []string{action, "OUTPUT", "-m", "owner", "!", "--uid-owner", iptablesOwnerUID()}
		base = append(base, extra...)
		base = append(base, "-m", "comment", "--comment", "gateway", "-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass")
		return base
	}

	switch proto {
	case "icmp":
		return [][]string{tagged("-p", "icmp")}
	case "tcp":
		dport := os.Getenv("GATEWAY_INTERCEPT_PORT")
		if dport == "" {
			dport = "443"
		}
		return [][]string{tagged(append([]string{"-p", "tcp", "--dport", dport}, flowStartMatches(maxPackets)...)...)}
	default: // "all"
		return [][]string{
			tagged(append([]string{"-p", "tcp"}, flowStartMatches(maxPackets)...)...),
			tagged(append([]string{"-p", "udp"}, flowStartMatches(maxPackets)...)...),
		}
	}
}

// getIptables6Rules returns the parallel ip6tables rules when IPv6 filtering is enabled
func getIptables6Rules(action string) [][]string {
	if !ipv6Enabled() {
		return nil
	}
	proto := interceptProtocol()
	maxPackets := interceptMaxPackets()

	tagged := func(extra ...string) []string {
		base := []string{action, "OUTPUT", "-m", "owner", "!", "--uid-owner", iptablesOwnerUID()}
		base = append(base, extra...)
		base = append(base, "-m", "comment", "--comment", "gateway", "-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass")
		return base
	}

	switch proto {
	case "icmp":
		return [][]string{tagged("-p", "ipv6-icmp")}
	case "tcp":
		dport := os.Getenv("GATEWAY_INTERCEPT_PORT")
		if dport == "" {
			dport = "443"
		}
		return [][]string{tagged(append([]string{"-p", "tcp", "--dport", dport}, flowStartMatches(maxPackets)...)...)}
	default:
		return [][]string{
			tagged(append([]string{"-p", "tcp"}, flowStartMatches(maxPackets)...)...),
			tagged(append([]string{"-p", "udp"}, flowStartMatches(maxPackets)...)...),
		}
	}
}

// dnsRedirEnabled reports whether the daemon should also take over the host's DNS
func dnsRedirEnabled() bool {
	return strings.TrimSpace(os.Getenv("GATEWAY_DNS_REDIRECT")) != "0"
}

// getDNSRedirectRules returns the nat-table rule that funnels the host's recursive DNS lookups into the local resolver
func getDNSRedirectRules(action string) [][]string {
	if !dnsRedirEnabled() {
		return nil
	}
	return [][]string{{
		"-t", "nat", action, "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-m", "owner", "!", "--uid-owner", iptablesOwnerUID(),
		"-m", "comment", "--comment", "gateway-dns",
		"-j", "REDIRECT", "--to-ports", dnsRedirectPort(),
	}}
}

// getDNSRedirect6Rules returns the ip6tables nat rule when IPv6 filtering is enabled
func getDNSRedirect6Rules(action string) [][]string {
	if !ipv6Enabled() || !dnsRedirEnabled() {
		return nil
	}
	return [][]string{{
		"-t", "nat", action, "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-m", "owner", "!", "--uid-owner", iptablesOwnerUID(),
		"-m", "comment", "--comment", "gateway-dns",
		"-j", "REDIRECT", "--to-ports", dnsRedirectPort(),
	}}
}

// iptablesOwnerUID returns the numeric uid whose sockets are excluded from interception
func iptablesOwnerUID() string {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_OWNER_UID")); v != "" {
		return v
	}
	return strconv.Itoa(os.Getuid())
}

// loadAPIToken returns the management-plane bearer token
func loadAPIToken() (string, error) {
	if tok := strings.TrimSpace(os.Getenv("GATEWAY_API_TOKEN")); tok != "" {
		return tok, nil
	}
	path := os.Getenv("GATEWAY_API_TOKEN_FILE")
	if path == "" {
		path = "gateway_token"
	}
	data, err := os.ReadFile(path)
	if err == nil {
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", path)
		}
		return tok, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading token file %s: %w", path, err)
	}

	// First run: generate and persist a token for this host.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	tok := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(tok), 0600); err != nil {
		return "", fmt.Errorf("writing token file %s: %w", path, err)
	}
	fmt.Printf("[API] Generated new bearer token in %s (0600); keep it secret.\n", path)
	return tok, nil
}

// installRuleTable checks (-C) and then inserts (-I) each tagged rule from the given builder
func installRuleTable(bin string, rules func(action string) [][]string) {
	insert := rules("-I")
	check := rules("-C")
	for i := range insert {
		fmt.Printf("\nSetting up %s rules (%s)...\n", bin, strings.Join(insert[i], " "))
		if err := exec.Command(bin, check[i]...).Run(); err == nil {
			fmt.Println("Rule already present; skipping.")
			continue
		}
		if err := exec.Command(bin, insert[i]...).Run(); err != nil {
			log.Printf("[WARNING] %s rule setup failed: %v", bin, err)
		}
	}
}

// removeRuleTable deletes (-D) every rule the builder can generate, so stale rules from a previous run are removed too
func removeRuleTable(bin string, rules func(action string) [][]string) {
	for _, args := range rules("-D") {
		fmt.Printf("\nCleaning up %s rules (%s)... Restoring normal internet.\n", bin, strings.Join(args, " "))
		cmd := exec.Command(bin, args...)
		if err := cmd.Run(); err != nil {
			log.Printf("[WARNING] %s cleanup failed: %v", bin, err)
		}
	}
}

// Setting up IPTables
func setupIptables() {
	installRuleTable("iptables", getIptablesRules)
	installRuleTable("iptables", getDNSRedirectRules)
	if ipv6Enabled() {
		installRuleTable("ip6tables", getIptables6Rules)
		installRuleTable("ip6tables", getDNSRedirect6Rules)
	}
}

// IPTables Cleaner
func cleanupIptables() {
	removeRuleTable("iptables", getIptablesRules)
	removeRuleTable("iptables", getDNSRedirectRules)
	if ipv6Enabled() {
		removeRuleTable("ip6tables", getIptables6Rules)
		removeRuleTable("ip6tables", getDNSRedirect6Rules)
	}
}
