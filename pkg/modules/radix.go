package modules

import (
	"strings"
	"sync"
)

// RadixTree is a concurrency safe suffix set of block domains
type RadixTree struct {
	mu     sync.RWMutex
	blocks map[string]string
}

func NewRadixTree() *RadixTree {
	return &RadixTree{
		blocks: make(map[string]string),
	}
}

// Insert adds a domain and its associated lists ID to the tree
func (rt *RadixTree) Insert(domain string, listID string) {
	domain = cleanDomain(domain)
	if domain == "" {
		return
	}
	if listID == "" {
		listID = domain
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.blocks[domain] = listID
}

// Remove deletes a single rule from the tree
func (rt *RadixTree) Remove(domain string) bool {
	domain = cleanDomain(domain)
	if domain == "" {
		return false
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if _, ok := rt.blocks[domain]; !ok {
		return false
	}
	delete(rt.blocks, domain)
	return true
}

// Domains returns a copy of every stored rule domain
func (rt *RadixTree) Domains() []string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	domains := make([]string, 0, len(rt.blocks))
	for d := range rt.blocks {
		domains = append(domains, d)
	}
	return domains
}

// Len reports how many rules are stored
func (rt *RadixTree) Len() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.blocks)
}

// Contains reports whether a rule exists with exactly this label
func (rt *RadixTree) Contains(domain string) bool {
	domain = cleanDomain(domain)
	if domain == "" {
		return false
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()
	_, ok := rt.blocks[domain]
	return ok
}

func (rt *RadixTree) match(domain string) (string, bool) {
	domain = cleanDomain(domain)
	if domain == "" {
		return "", false
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	for {
		if id, ok := rt.blocks[domain]; ok {
			return id, true
		}
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			return "", false
		}
		domain = domain[i+1:]
	}
}

// Match checks if a domain or any of its parent sbudomains are blocked
func (rt *RadixTree) Match(domain string) (string, bool) {
	return rt.match(domain)
}

// Search checks if a domain or any parent label suffix is blocked
func (rt *RadixTree) Search(domain string) bool {
	_, ok := rt.match(domain)
	return ok
}
