package modules

import (
	"context"
	"middleware/pkg/pipeline"
)

type DynamicBlocklistModule struct {
	radix *RadixTree
	store PersistentState
}

// NewDynamicBlocklistModule bilds the runtime blocklistfor any persisted entries
func NewDynamicBlocklistModule(initialDomains []string, store PersistentState) *DynamicBlocklistModule {
	m := NewRadixTree()
	if store != nil {
		if persisted, err := store.ListDynamicDomains(); err == nil {
			for _, d := range persisted {
				if cleaned := cleanDomain(d); cleaned != "" {
					m.Insert(cleaned, "")
				}
			}
		}
	}
	for _, d := range initialDomains {
		m.Insert(d, "")
	}
	return &DynamicBlocklistModule{radix: m, store: store}
}

func (b *DynamicBlocklistModule) Name() string {
	return "DynamicBlocklist"
}

func (b *DynamicBlocklistModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	// Suffix semantics: block on the query itself or any parent label.
	if _, ok := b.radix.Match(tctx.Domain); ok {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = b.Name()
		tctx.BlockReason = "matched runtime blocklist rule"
		return true, nil
	}
	return false, nil
}

// AddDomain blocks a domain and, under suffix semantics, every subdomain of it.
func (b *DynamicBlocklistModule) AddDomain(domain string) bool {
	d := cleanDomain(domain)
	if d == "" {
		return false
	}

	if b.radix.Contains(d) {
		return false
	}
	b.radix.Insert(d, "")
	if b.store != nil {
		b.store.AddDynamicDomain(d)
	}
	return true
}

// RemoveDomain un-blocks a single exact rule under suffix semantics
func (b *DynamicBlocklistModule) RemoveDomain(domain string) bool {
	d := cleanDomain(domain)
	if d == "" || !b.radix.Remove(d) {
		return false
	}
	if b.store != nil {
		b.store.RemoveDynamicDomain(d)
	}
	return true
}

// ListDomains returns a copy of all current rules.
func (b *DynamicBlocklistModule) ListDomains() []string {
	return b.radix.Domains()
}
