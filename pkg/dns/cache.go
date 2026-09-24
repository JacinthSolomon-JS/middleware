package dns

import (
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultCacheEntries Bounds the resolver answer cache (invariant 4)
const DefaultCacheEntries = 4096

// To cap how long a positive answer is cached (protects against a hostile upstream)
const maxCacheTTL = time.Hour

// For NXDOMAIN answers
const negativeCacheTTL = 60 * time.Second

type dnsCache struct {
	mu       sync.Mutex
	m        map[string]cacheEntry
	max      int
	overflow uint64
}

type cacheEntry struct {
	msg    *dns.Msg
	expire time.Time
}

func newDNSCache(maxEntries int) *dnsCache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheEntries
	}
	return &dnsCache{m: make(map[string]cacheEntry, maxEntries), max: maxEntries}
}

// get returns a copy of a live cached message, or nil
func (c *dnsCache) get(key string) *dns.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil
	}

	if !time.Now().Before(e.expire) {
		delete(c.m, key)
		return nil
	}
	return e.msg.Copy()
}

func (c *dnsCache) put(key string, msg *dns.Msg, ttl time.Duration) {
	if msg == nil || ttl <= 0 {
		return
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		now := time.Now()
		for k, e := range c.m {
			if !e.expire.After(now) {
				delete(c.m, k)
				break
			}
		}
	}
	if len(c.m) >= c.max {
		c.overflow++
		return
	}
	c.m[key] = cacheEntry{msg: msg.Copy(), expire: time.Now().Add(ttl)}
}

// Overflow Reports how many insertions were skipped at capacity.
func (c *dnsCache) Overflow() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflow
}

func (c *dnsCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// Returns the caching TTL for a response
func answerTTL(m *dns.Msg) time.Duration {
	if m == nil {
		return 0
	}
	switch m.Rcode {
	case dns.RcodeNameError:
		return negativeCacheTTL
	case dns.RcodeSuccess:
		// fall through
	default:
		return 0
	}
	min := time.Duration(math.MaxInt64)
	found := false
	for _, rr := range m.Answer {
		t := time.Duration(rr.Header().Ttl) * time.Second
		if t < min {
			min = t
		}
		found = true
	}
	if !found || min <= 0 {
		return 0
	}
	if min > maxCacheTTL {
		return maxCacheTTL
	}
	return min
}

// Names an answer cache entry
func cacheKey(domain string, qtype uint16) string {
	return domain + "/" + strconv.FormatUint(uint64(qtype), 10)
}
