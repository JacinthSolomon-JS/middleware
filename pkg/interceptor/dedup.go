package interceptor

import (
	"sync"
	"time"
)

const Ki08DedupeWindow = 30 * time.Second

// MaxDedupeEntries bounds the block-dedupe map (invariant 4)
const MaxDedupeEntries = 4096

// blockDedupe remembers recently-blocked flow keys (dstIP+domain) and reports
type blockDedupe struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	lifetime time.Duration
	overflow uint64
}

func newBlockDedupe(lifetime time.Duration) *blockDedupe {
	return &blockDedupe{seen: make(map[string]time.Time), lifetime: lifetime}
}

// emittable reports whether this flow key should emit now
func (d *blockDedupe) emittable(dstIP, domain string) bool {
	now := time.Now()
	exp := now.Add(-d.lifetime)
	k := dstIP + "\x00" + domain

	d.mu.Lock()
	defer d.mu.Unlock()

	for k2, t := range d.seen {
		if t.Before(exp) {
			delete(d.seen, k2)
		}
	}
	if t, ok := d.seen[k]; ok && !t.Before(exp) {
		return false
	}
	if len(d.seen) >= MaxDedupeEntries {
		d.overflow++
		return true // fail-open under pressure: count and emit
	}
	d.seen[k] = now
	return true
}

// Overflow returns how many keys were emitted under memory pressure instead of deduped
func (d *blockDedupe) Overflow() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.overflow
}
