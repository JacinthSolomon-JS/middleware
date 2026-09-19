package modules

import (
	"context"
	"fmt"
	"middleware/pkg/pipeline"
	"strings"
	"sync"
)

type DynamicBlocklistModule struct {
	mu      sync.RWMutex
	blocked map[string]bool
}

func NewDynamicBlocklistModule(initialDomains []string) *DynamicBlocklistModule {
	m := make(map[string]bool)
	for _, d := range initialDomains {
		m[cleanDomain(d)] = true
	}
	return &DynamicBlocklistModule{blocked: m}
}

func (b *DynamicBlocklistModule) Name() string {
	return "DynamicBlocklist"
}

func cleanDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
}

func (b *DynamicBlocklistModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	domain := cleanDomain(tctx.Domain)

	b.mu.RLock()
	isBlocked := b.blocked[domain]
	b.mu.RUnlock()

	if isBlocked {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = b.Name()
		tctx.BlockReason = fmt.Sprintf("[Blocked] Domain '%s' matched dynamic blocklist rule", domain)
		return true, nil
	}
	return false, nil
}

// To Add Domain to active blocklist in real time
func (b *DynamicBlocklistModule) AddDomain(domain string) {
	d := cleanDomain(domain)
	if d == "" {
		return
	}
	b.mu.Lock()
	b.blocked[d] = true
	b.mu.Unlock()
}

// RemoveDomain to unblock a domain in realtime
func (b *DynamicBlocklistModule) RemoveDomain(domain string) {
	d := cleanDomain(domain)
	b.mu.Lock()
	delete(b.blocked, d)
	b.mu.Unlock()
}

// ListDomains to list copy of all current rules
func (b *DynamicBlocklistModule) ListDomains() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domains := make([]string, 0, len(b.blocked))
	for d := range b.blocked {
		domains = append(domains, d)
	}
	return domains
}
