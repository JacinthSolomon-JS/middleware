package modules

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"middleware/pkg/pipeline"
	"middleware/pkg/storage"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

const maxFeedBodyBytes = 32 << 20 // 32 MiB cap on feed downloads

var sourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func closeResource(resource string, closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Printf("[WARNING] - BlocklistManager: failed to close %s: %v", resource, err)
	}
}

type BlocklistConfig struct {
	Version     string            `yaml:"version"`
	UpdatedAt   string            `yaml:"updated_at"`
	Description string            `yaml:"description"`
	Sources     []BlocklistSource `yaml:"sources"`
}
type BlocklistSource struct {
	ID          string    `yaml:"id" json:"id"`
	Name        string    `yaml:"name" json:"name"`
	Category    string    `yaml:"category" json:"category"`
	Type        string    `yaml:"type" json:"type"` // "preset", "url", or "file"
	URL         string    `yaml:"url" json:"url"`   // remote feed URL or (legacy) local file path
	Path        string    `yaml:"path" json:"-"`    // local list path for file-type sources (never exposed)
	Active      bool      `yaml:"enabled" json:"active"`
	DomainCount int       `yaml:"-" json:"domain_count"`
	LastUpdated time.Time `yaml:"-" json:"last_updated"`
	Cache       []string  `yaml:"-" json:"-"`
}

type BlocklistManagerModule struct {
	mu         sync.RWMutex
	refreshMu  sync.Mutex
	radixTree  atomic.Pointer[RadixTree]
	sources    map[string]*BlocklistSource
	configPath string
	httpClient *http.Client
	cacheDir   string
	store      PersistentState
}

func NewBlocklistManagerModule(configPath string) (*BlocklistManagerModule, error) {
	return newBlocklistManager(configPath, "./data/cache")
}

// NewBlocklistManagerModuleWithStore builds the manager with state persistence
func NewBlocklistManagerModuleWithStore(configPath string, store PersistentState) (*BlocklistManagerModule, error) {
	return newBlocklistManagerWithStore(configPath, "./data/cache", store)
}

func newBlocklistManager(configPath, cacheDir string) (*BlocklistManagerModule, error) {
	return newBlocklistManagerWithStore(configPath, cacheDir, nil)
}

func newBlocklistManagerWithStore(configPath, cacheDir string, store PersistentState) (*BlocklistManagerModule, error) {
	m := &BlocklistManagerModule{
		sources:    make(map[string]*BlocklistSource),
		configPath: configPath,
		httpClient: newFeedClient(),
		cacheDir:   cacheDir,
		store:      store,
	}
	m.radixTree.Store(NewRadixTree())

	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("[ERROR]: Failed to create cache directory: %w", err)
	}

	if err := m.LoadConfigFromFile(configPath); err != nil {
		return nil, err
	}

	return m, nil
}

// newFeedClient builds an HTTP client that only talks to public HTTPS hosts
func newFeedClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid feed address %q", addr)
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("could not resolve %q: %w", host, err)
		}
		target, err := pickFeedTarget(port, ips)
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, target)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after %d redirects", len(via))
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid feed address %q", addr)
				}
				conn, err := dial(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}), nil
			},
			DialContext: dial,
		},
	}
}

// pickFeedTarget selects the first public address from a resolution result
func pickFeedTarget(port string, ips []net.IP) (string, error) {
	for _, ip := range ips {
		if isPublicIP(ip) {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", fmt.Errorf("no public address to fetch (resolution returned only private/loopback/link-local/multicast IPs)")
}

func isPublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast())
}

func validSourceID(id string) bool {
	return sourceIDPattern.MatchString(id)
}

func (b *BlocklistManagerModule) Name() string {
	return "BlocklistManager"
}

func (b *BlocklistManagerModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	tree := b.radixTree.Load()
	if tree == nil {
		return false, nil
	}

	if listID, ok := tree.Match(tctx.Domain); ok {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = listID
		tctx.BlockReason = fmt.Sprintf("matched blocklist source '%s'", listID)
		return true, nil
	}
	return false, nil
}

// LoadConfigFromFile reads list configuration from the YAML file
func (b *BlocklistManagerModule) LoadConfigFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("[ERROR]: Failed to read blocklist config %s: %w", filePath, err)
	}

	var cfg BlocklistConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("[ERROR]: Failed to parse blocklist yaml %s: %w", filePath, err)
	}

	// Read and parse before taking the lock so an error can never leave the mutex locked
	sources := make(map[string]*BlocklistSource, len(cfg.Sources))
	for i := range cfg.Sources {
		s := cfg.Sources[i]
		if s.Type == "" {
			s.Type = "preset"
		}
		if !validSourceID(s.ID) {
			return fmt.Errorf("[ERROR]: invalid source id %q", s.ID)
		}

		if s.Type == "file" && s.Path != "" {
			if file, err := os.Open(s.Path); err == nil {
				s.Cache = parseHostFormat(file)
				s.DomainCount = len(s.Cache)
				closeResource(s.Path, file)
			}
		}
		if len(s.Cache) == 0 {
			// Attempt to load from the disk cache first; network refresh below fills gaps.
			if file, err := os.Open(b.cachePathFor(s.ID)); err == nil {
				s.Cache = parseHostFormat(file)
				s.DomainCount = len(s.Cache)
				closeResource(b.cachePathFor(s.ID), file)
			}
		}

		sources[s.ID] = &s
	}

	// Restore runtime state before the manager is exposed
	if b.store != nil {
		b.applyPersistedState(sources)
	}

	b.mu.Lock()
	b.sources = sources
	b.rebuildRulesLocked()
	b.mu.Unlock()

	return nil
}

func (b *BlocklistManagerModule) cachePathFor(id string) string {
	return filepath.Join(b.cacheDir, id+".txt")
}

// applyPersistedState restores runtime added custom sources and per source toggles from the store into a freshly parsed source map.
func (b *BlocklistManagerModule) applyPersistedState(sources map[string]*BlocklistSource) {
	customs, err := b.store.ListCustomSources()
	if err != nil {
		log.Printf("[WARNING] - BlocklistManager: failed to load custom sources: %v", err)
	} else {
		for _, c := range customs {
			if _, dup := sources[c.ID]; dup {
				continue
			}
			s := &BlocklistSource{
				ID:       c.ID,
				Name:     c.Name,
				Category: "Custom Lists",
				Type:     c.Type,
				URL:      c.URL,
				Active:   c.Active,
			}
			if file, err := os.Open(b.cachePathFor(c.ID)); err == nil {
				s.Cache = parseHostFormat(file)
				s.DomainCount = len(s.Cache)
				closeResource(b.cachePathFor(c.ID), file)
			}
			sources[s.ID] = s
		}
	}

	toggles, err := b.store.ListSourceToggles()
	if err != nil {
		log.Printf("[WARNING] - BlocklistManager: failed to load source toggles: %v", err)
		return
	}
	for id, active := range toggles {
		if src, ok := sources[id]; ok {
			src.Active = active
		}
	}
}

// persistToggle writes a source's Active flag to the store, logging
func (b *BlocklistManagerModule) persistToggle(id string, active bool) {
	if b.store == nil {
		return
	}
	if err := b.store.SaveSourceToggle(id, active); err != nil {
		log.Printf("[WARNING] - BlocklistManager: failed to persist toggle for %s: %v", id, err)
	}
}

// persistCustomSource writes a runtime-added source to the store
func (b *BlocklistManagerModule) persistCustomSource(c storage.CustomSource) {
	if b.store == nil {
		return
	}
	if err := b.store.SaveCustomSource(c); err != nil {
		log.Printf("[WARNING] - BlocklistManager: failed to persist custom source %s: %v", c.ID, err)
	}
}

// RefreshAllEnabled fetches updates for all enabled remote blocklists, then rebuilds the trie.
func (b *BlocklistManagerModule) RefreshAllEnabled() {
	b.mu.RLock()
	var toRefresh []string
	for id, src := range b.sources {
		if src.Active && src.Type != "file" && src.URL != "" {
			toRefresh = append(toRefresh, id)
		}
	}
	b.mu.RUnlock()

	fetched := make(map[string][]string, len(toRefresh))
	for _, id := range toRefresh {
		domains, err := b.fetchSource(id)
		if err != nil {
			log.Printf("[WARNING] - BlocklistManager: failed to refresh source %s: %v", id, err)
			continue
		}
		fetched[id] = domains
	}

	if len(fetched) == 0 {
		return
	}

	b.mu.Lock()
	for id, domains := range fetched {
		if src, ok := b.sources[id]; ok {
			src.Cache = domains
			src.DomainCount = len(domains)
			src.LastUpdated = time.Now()
		}
	}
	b.rebuildRulesLocked()
	b.mu.Unlock()
}

// TelemetryAutoRefreshInterval is how often enabled telemetry/tracking sources and re-imports
const TelemetryAutoRefreshInterval = 2 * time.Hour

// StartTelemetryRefresh re-imports enabled telemetry sources on an interval
func (b *BlocklistManagerModule) StartTelemetryRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = TelemetryAutoRefreshInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	b.RefreshTelemetry()
	for {
		select {
		case <-ticker.C:
			b.RefreshTelemetry()
		case <-ctx.Done():
			return
		}
	}
}

// RefreshTelemetry re-imports every enabled telemetry source
func (b *BlocklistManagerModule) RefreshTelemetry() {
	b.refreshMu.Lock()
	defer b.refreshMu.Unlock()

	b.mu.RLock()
	var toRefresh []string
	for id, src := range b.sources {
		if src.Active && src.Type == "file" && src.Path != "" {
			toRefresh = append(toRefresh, id)
		}
	}
	b.mu.RUnlock()

	fetched := make(map[string][]string, len(toRefresh))
	for _, id := range toRefresh {
		domains, err := b.fetchSource(id)
		if err != nil {
			log.Printf("[WARNING] - BlocklistManager: telemetry refresh failed for %s: %v", id, err)
			continue
		}
		fetched[id] = domains
	}

	if len(fetched) == 0 {
		return
	}

	b.mu.Lock()
	for id, domains := range fetched {
		if src, ok := b.sources[id]; ok {
			src.Cache = domains
			src.DomainCount = len(domains)
			src.LastUpdated = time.Now()
		}
	}
	b.rebuildRulesLocked()
	b.mu.Unlock()
}

// AddCustomURL adds a custom remote blocklist URL
func (b *BlocklistManagerModule) AddCustomURL(id string, name string, rawURL string) error {
	if !validSourceID(id) {
		return fmt.Errorf("invalid source id %q", id)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("source URL must be a valid https URL")
	}

	b.mu.Lock()
	if _, exists := b.sources[id]; exists {
		b.mu.Unlock()
		return fmt.Errorf("source '%s' already exists", id)
	}
	b.sources[id] = &BlocklistSource{
		ID:       id,
		Name:     name,
		Category: "Custom Lists",
		Type:     "url",
		URL:      rawURL,
		Active:   true,
	}
	b.mu.Unlock()

	b.persistCustomSource(storage.CustomSource{ID: id, Name: name, Type: "url", URL: rawURL, Active: true})
	b.persistToggle(id, true)

	return b.RefreshSource(id)
}

// ImportFile reads domains from a local hostfile/text file
func (b *BlocklistManagerModule) ImportFile(id string, name string, filePath string) error {
	if !validSourceID(id) {
		return fmt.Errorf("invalid source id %q", id)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer closeResource(filePath, file)

	domains := parseHostFormat(file)

	b.mu.Lock()
	b.sources[id] = &BlocklistSource{
		ID:          id,
		Name:        name,
		Category:    "Custom Lists",
		Type:        "file",
		URL:         filePath,
		Active:      true,
		DomainCount: len(domains),
		LastUpdated: time.Now(),
		Cache:       domains,
	}
	b.rebuildRulesLocked()
	b.mu.Unlock()

	b.persistCustomSource(storage.CustomSource{ID: id, Name: name, Type: "file", URL: filePath, Active: true})
	b.persistToggle(id, true)

	return nil
}

// ToggleSource enables or disables a list by ID
func (b *BlocklistManagerModule) ToggleSource(id string, enable bool) error {
	b.mu.Lock()
	src, exists := b.sources[id]
	if !exists {
		b.mu.Unlock()
		return fmt.Errorf("source '%s' not found", id)
	}

	src.Active = enable
	needRefresh := enable && src.DomainCount == 0
	b.mu.Unlock()

	b.persistToggle(id, enable)

	if needRefresh {
		return b.RefreshSource(id)
	}

	b.mu.Lock()
	b.rebuildRulesLocked()
	b.mu.Unlock()
	return nil
}

// RefreshSource fetches updated rules for a URL/Preset source and rebuilds the trie from all sources.
func (b *BlocklistManagerModule) RefreshSource(id string) error {
	domains, err := b.fetchSource(id)
	if err != nil {
		return err
	}

	b.mu.Lock()
	if src, ok := b.sources[id]; ok {
		src.Cache = domains
		src.DomainCount = len(domains)
		src.LastUpdated = time.Now()
	}
	b.rebuildRulesLocked()
	b.mu.Unlock()
	return nil
}

// fetchSource downloads, parses, and validates one source's feed without touching the trie or the sources map.
func (b *BlocklistManagerModule) fetchSource(id string) ([]string, error) {
	if !validSourceID(id) {
		return nil, fmt.Errorf("invalid source id %q", id)
	}
	b.mu.RLock()
	src, exists := b.sources[id]
	if !exists || !src.Active {
		b.mu.RUnlock()
		return nil, fmt.Errorf("source '%s' inactive or not found", id)
	}
	srcURL := src.URL
	filePath := src.Path
	b.mu.RUnlock()

	if src.Type == "file" {
		return b.fetchFileSource(id, srcURL, filePath)
	}

	if srcURL == "" {
		return nil, fmt.Errorf("source '%s' has no URL", id)
	}

	u, err := url.Parse(srcURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("[ERROR]: source %s must use an https URL", id)
	}

	domains, err := b.downloadFeed(id, srcURL)
	if err != nil {
		return nil, err
	}

	if err := b.writeCache(id, domains); err != nil {
		log.Printf("[WARNING] - BlocklistManager: failed to write cache for %s: %v", id, err)
	}

	return domains, nil
}

// fetchFileSource handles file-type sources.
func (b *BlocklistManagerModule) fetchFileSource(id, srcURL, path string) ([]string, error) {
	if path == "" && srcURL != "" {
		// Legacy custom imports keep the local path in URL.
		if u, err := url.Parse(srcURL); err == nil && u.Scheme == "" && u.Host == "" {
			path = srcURL
		}
	}
	if path == "" {
		return nil, fmt.Errorf("source '%s' has no local path or import URL", id)
	}

	if u, err := url.Parse(srcURL); err == nil && u.Scheme == "https" && u.Host != "" {
		domains, err := b.downloadFeed(id, srcURL)
		if err != nil {
			return nil, err
		}
		if err := b.writeFileAtomically(path, domains); err != nil {
			log.Printf("[WARNING] - BlocklistManager: failed to import %s into %s: %v", id, path, err)
		}
		return domains, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open local list %s: %w", path, err)
	}
	defer closeResource(path, file)
	return parseHostFormat(file), nil
}

// downloadFeed fetches, bounds, parses, and validates one HTTPS feed without touching caches
func (b *BlocklistManagerModule) downloadFeed(id, srcURL string) ([]string, error) {
	resp, err := b.httpClient.Get(srcURL)
	if err != nil {
		return nil, err
	}
	defer closeResource("response body for "+srcURL, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[ERROR]: HTTP error %d fetching %s", resp.StatusCode, srcURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxFeedBodyBytes {
		return nil, fmt.Errorf("[ERROR]: feed %s exceeds %d byte limit", id, maxFeedBodyBytes)
	}

	domains, skipped := parseHostFormatStats(bytes.NewReader(body))

	if len(domains) == 0 {
		return nil, fmt.Errorf("[ERROR]: feed %s produced no usable domains; keeping previous list", id)
	}

	if skipped > 0 {
		log.Printf("[WARNING] - BlocklistManager: feed %s: skipped %d non-hostname line(s); %d rules kept", id, skipped, len(domains))
	}

	return domains, nil
}

// writeFileAtomically writes domains to path via temp file + rename so a crash mid-write never leaves a truncated local list.
func (b *BlocklistManagerModule) writeFileAtomically(path string, domains []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	clean := false
	defer func() {
		if !clean {
			os.Remove(tmp)
		}
	}()

	var sb strings.Builder
	for _, d := range domains {
		sb.WriteString(d)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(tmp, []byte(sb.String()), 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	clean = true
	return nil
}

// writeCache atomically replaces the local cache file for a source.
func (b *BlocklistManagerModule) writeCache(id string, domains []string) error {
	tmp := b.cachePathFor(id) + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	clean := false
	defer func() {
		if !clean {
			os.Remove(tmp)
		}
	}()

	for _, d := range domains {
		if _, err := f.WriteString(d + "\n"); err != nil {
			return errors.Join(err, f.Close())
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.cachePathFor(id)); err != nil {
		return err
	}
	clean = true
	return nil
}

// ListSources returns copies of all configured sources
func (b *BlocklistManagerModule) ListSources() []BlocklistSource {
	b.mu.RLock()
	defer b.mu.RUnlock()

	list := make([]BlocklistSource, 0, len(b.sources))
	for _, src := range b.sources {
		list = append(list, *src)
	}
	return list
}

// CategoryInfo summarizes the sources grouped under one category.
type CategoryInfo struct {
	Name    string            `json:"name"`
	Enabled int               `json:"enabled"`
	Total   int               `json:"total"`
	Domains int               `json:"domains"`
	Sources []BlocklistSource `json:"sources"`
}

// ListCategories returns every configured category (alphabetical, "CustomLists" last)
func (b *BlocklistManagerModule) ListCategories() []CategoryInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()

	order := make([]string, 0, 8)
	byName := make(map[string]*CategoryInfo, 8)
	for _, src := range b.sources {
		cat := src.Category
		if cat == "" {
			cat = "Other"
		}
		ci, ok := byName[cat]
		if !ok {
			ci = &CategoryInfo{Name: cat}
			byName[cat] = ci
			order = append(order, cat)
		}
		ci.Total++
		if src.Active {
			ci.Enabled++
			ci.Domains += src.DomainCount
		}
		ci.Sources = append(ci.Sources, *src)
	}

	// Deterministic order: alphabetical, "Custom Lists" always last.
	sorted := make([]string, 0, len(order))
	for _, cat := range order {
		if cat != "Custom Lists" {
			sorted = append(sorted, cat)
		}
	}
	sort.Strings(sorted)
	sorted = append(sorted, "Custom Lists")

	out := make([]CategoryInfo, 0, len(sorted))
	for _, cat := range sorted {
		if ci, ok := byName[cat]; ok {
			sort.Slice(ci.Sources, func(i, j int) bool { return ci.Sources[i].ID < ci.Sources[j].ID })
			out = append(out, *ci)
		}
	}
	return out
}

// ToggleCategory enables or disables every source in a category
func (b *BlocklistManagerModule) ToggleCategory(name string, enable bool) error {
	b.mu.Lock()
	var toEnable, needFetch, toDisable []string
	found := false
	for _, src := range b.sources {
		cat := src.Category
		if cat == "" {
			cat = "Other"
		}
		if cat != name {
			continue
		}
		found = true
		if enable {
			if src.Active {
				continue
			}
			toEnable = append(toEnable, src.ID)
			if src.DomainCount == 0 {
				needFetch = append(needFetch, src.ID)
			}
		} else if src.Active {
			toDisable = append(toDisable, src.ID)
		}
	}
	if !found {
		b.mu.Unlock()
		return fmt.Errorf("category '%s' not found", name)
	}

	for _, id := range toEnable {
		if src, ok := b.sources[id]; ok {
			src.Active = true
		}
	}
	for _, id := range toDisable {
		if src, ok := b.sources[id]; ok {
			src.Active = false
		}
	}
	b.mu.Unlock()

	fetched := make(map[string][]string, len(needFetch))
	var firstErr error
	for _, id := range needFetch {
		domains, err := b.fetchSource(id)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		fetched[id] = domains
	}

	b.mu.Lock()
	for id, domains := range fetched {
		if src, ok := b.sources[id]; ok {
			src.Cache = domains
			src.DomainCount = len(domains)
			src.LastUpdated = time.Now()
		}
	}
	b.rebuildRulesLocked()
	b.mu.Unlock()

	for _, id := range toEnable {
		b.persistToggle(id, true)
	}
	for _, id := range toDisable {
		b.persistToggle(id, false)
	}

	return firstErr
}

func (b *BlocklistManagerModule) rebuildRulesLocked() {
	newTree := NewRadixTree()

	for _, src := range b.sources {
		if !src.Active {
			continue
		}
		if src.Type == "file" && len(src.Cache) == 0 {
			path := src.Path
			if path == "" {
				path = src.URL // legacy custom imports carry the local path in URL
			}
			if file, err := os.Open(path); err == nil {
				src.Cache = parseHostFormat(file)
				src.DomainCount = len(src.Cache)
				closeResource(path, file)
			}
		}

		for _, d := range src.Cache {
			newTree.Insert(d, src.ID)
		}
	}
	b.radixTree.Store(newTree)
}

func parseHostFormat(r io.Reader) []string {
	domains, _ := parseHostFormatStats(r)
	return domains
}

// parseHostFormatStats parses a hostfile/filter list into rules
func parseHostFormatStats(r io.Reader) ([]string, int) {
	var domains []string
	skipped := 0
	scanner := bufio.NewScanner(r)
	// Support long lines up to 1MB (e.g. minified filter lists)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Strip inline comments starting with '#' or '!'
		if idx := strings.IndexAny(line, "#!"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		// Support Adblock Plus syntax: ||example.com^
		if after, ok := strings.CutPrefix(line, "||"); ok {
			idx := strings.IndexByte(after, '^')
			if idx < 0 {
				skipped++ // malformed ABP rule (no "^" terminator)
				continue
			}
			if rest := after[idx+1:]; rest != "" {
				skipped++ // options ("^$domain=") or trailing garbage: not unconditional
				continue
			}
			host := after[:idx]
			if strings.Contains(host, "/") {
				skipped++ // path rule "||host/path^": would block the whole zone
				continue
			}
			d := cleanDomain(host)
			if isValidDomain(d) {
				domains = append(domains, d)
			} else {
				skipped++
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1" || fields[0] == "::1" || fields[0] == "::") {
			d := cleanDomain(fields[1])
			if isValidDomain(d) {
				domains = append(domains, d)
			} else {
				skipped++
			}
		} else if len(fields) >= 1 {
			d := cleanDomain(fields[0])
			if isValidDomain(d) {
				domains = append(domains, d)
			} else {
				skipped++
			}
		} else {
			skipped++
		}
	}

	return domains, skipped
}

// isValidDomain rejects lines that are not real hostnames
func isValidDomain(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" || len(d) > 253 || strings.ContainsAny(d, " \t/") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false
	}
	if strings.Contains(d, "*") {
		return false
	}

	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, r := range l {
			if !(r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return false
			}
		}
	}
	return true
}

func cleanDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	domain = strings.TrimPrefix(domain, "||")
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "^")
	domain = strings.Trim(domain, ".")
	return domain
}
