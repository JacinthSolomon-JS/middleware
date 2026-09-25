package modules

import (
	"context"
	"middleware/pkg/pipeline"
	"strings"
	"sync"
)

// AllowlistModule always passes a matching domain before any block module
type AllowlistModule struct {
	mu      sync.RWMutex
	allowed map[string]struct{}
	store   PersistentState
}

func NewAllowlistModule(initialDomains []string, store PersistentState) *AllowlistModule {
	m := &AllowlistModule{allowed: make(map[string]struct{}), store: store}
	if store != nil {
		if persisted, err := store.ListAllowlistDomains(); err == nil {
			for _, d := range persisted {
				m.insert(d)
			}
		}
	}
	for _, d := range initialDomains {
		m.insert(d)
	}
	return m
}

func (a *AllowlistModule) Name() string { return "Allowlist" }

func (a *AllowlistModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	if a.isAllowed(cleanDomain(tctx.Domain)) {
		tctx.FinalAction = pipeline.ActionAllow
		tctx.MatchedBy = a.Name()
		tctx.BlockReason = ""
		return true, nil
	}
	return false, nil
}

// isAllowed walks the query and each parent-label suffix, allocation-free.
func (a *AllowlistModule) isAllowed(domain string) bool {
	if domain == "" {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for {
		if _, ok := a.allowed[domain]; ok {
			return true
		}
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			return false
		}
		domain = domain[i+1:]
	}
}

func (a *AllowlistModule) insert(domain string) {
	if d := cleanDomain(domain); d != "" {
		a.allowed[d] = struct{}{}
	}
}

// AddDomain allowlists a domain (and its subdomains, suffix semantics).
func (a *AllowlistModule) AddDomain(domain string) {
	d := cleanDomain(domain)
	if d == "" {
		return
	}
	a.mu.Lock()
	a.allowed[d] = struct{}{}
	a.mu.Unlock()
	if a.store != nil {
		a.store.AddAllowlistDomain(d)
	}
}

// RemoveDomain stops allowlisting a domain.
func (a *AllowlistModule) RemoveDomain(domain string) {
	d := cleanDomain(domain)
	a.mu.Lock()
	delete(a.allowed, d)
	a.mu.Unlock()
	if a.store != nil {
		a.store.RemoveAllowlistDomain(d)
	}
}

// ListDomains returns a copy of the current allowlist entries.
func (a *AllowlistModule) ListDomains() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.allowed))
	for d := range a.allowed {
		out = append(out, d)
	}
	return out
}
