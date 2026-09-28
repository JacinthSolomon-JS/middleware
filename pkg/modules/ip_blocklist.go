package modules

import (
	"context"
	"errors"
	"fmt"
	"middleware/pkg/pipeline"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

// MaxIPBlocklistEntries bounds the runtime IP/CIDR blocklist
const MaxIPBlocklistEntries = 4096

var (
	// ErrIPBlocklistFull is returned by Add wheb the runtime list is at cap
	ErrIPBlocklistFull = errors.New("[ERROR]: IP Blocklist is Full")
	// ErrInvalidIPAddress is returned when an entry is not an IP or CIDR
	ErrInvalidIPAddress = errors.New("[ERROR]: Invalid IP Address or CIDR")
)

// ipNode is one node of a binary prefix tire over an address bits
type ipNode struct {
	next [2]*ipNode
	end  bool
}

type ipTire struct {
	v4, v6 *ipNode
}

func (t *ipTire) insert(p netip.Prefix) {
	a := p.Addr()
	bits := p.Bits()
	if bits > a.BitLen() {
		bits = a.BitLen()
	}

	var root **ipNode
	if a.Is4() {
		root = &t.v4
	} else {
		root = &t.v6
	}
	if *root == nil {
		*root = &ipNode{}
	}

	n := *root
	for i := 0; i < bits; i++ {
		b := bitAt(a, i)
		if n.next[b] == nil {
			n.next[b] = &ipNode{}
		}
		n = n.next[b]
	}
	n.end = true
}

func (t *ipTire) contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()

	var root *ipNode
	max := 128
	if a.Is4() {
		root = t.v4
		max = 32
	} else {
		root = t.v6
	}
	if root == nil {
		return false
	}
	return trieWalk(root, a, max)
}

// bitAt extracts the i-th most significant bit of an address
func bitAt(a netip.Addr, i int) int {
	if a.Is4() {
		b := a.As4()
		return int((b[i/8] >> (7 - uint(i%8))) & 1)
	}
	b := a.As16()
	return int((b[i/8] >> (7 - uint(i%8))) & 1)
}

// parseIPPrefix cannonicalizes a user supplied IP/CIDR
func parseIPPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("%w %q", ErrInvalidIPAddress, s)
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%w %q", ErrInvalidIPAddress, s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}

	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w %q", ErrInvalidIPAddress, s)
	}
	a, bits := p.Addr(), p.Bits()
	if a.Is4In6() {
		// Fold ::ffff:a.b.c.d/nnn to a.b.c.d/(nnn-96) so v4 rules match v4.
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("%w %q", ErrInvalidIPAddress, s)
		}
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked(), nil
}

// IPBlocklistModule is the runtime malicious IP layer
type IPBlocklistModule struct {
	mu       sync.RWMutex
	entries  []netip.Prefix
	trie     atomic.Pointer[ipTire]
	store    PersistentState
	overflow atomic.Uint64
}

// IPBlocklistModule loads any persisted entries form the store
func NewIPBlocklistModule(store PersistentState) *IPBlocklistModule {
	b := &IPBlocklistModule{store: store}
	b.trie.Store(&ipTire{})
	if store != nil {
		if persisted, err := store.ListDynamicIPs(); err == nil {
			for _, s := range persisted {
				if len(b.entries) >= MaxIPBlocklistEntries {
					b.overflow.Add(1)
					continue
				}
				if p, err := parseIPPrefix(s); err == nil {
					b.entries = append(b.entries, p)
				}
			}
		}
		b.rebuildLocked()
	}
	return b
}

func (b *IPBlocklistModule) Name() string {
	return "IPBlocklist"
}

// Inspect blocks the context when its destination IP falls inside blocked
func (b *IPBlocklistModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	if tctx.DstIP == nil {
		return false, nil
	}
	a, ok := netip.AddrFromSlice(tctx.DstIP)
	if !ok || !b.Contains(a) {
		return false, nil
	}
	tctx.FinalAction = pipeline.ActionBlock
	tctx.MatchedBy = b.Name()
	tctx.BlockReason = fmt.Sprintf("[BLOCKED] - Destination IP %s matched IP blocklist", a.Unmap().String())
	return true, nil
}

// Contains reports whether an address is inside a blocked prefix
func (b *IPBlocklistModule) Contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	t := b.trie.Load()
	if t == nil {
		return false
	}
	if a.Is4() {
		if t.v4 == nil {
			return false
		}
		return trieWalk(t.v4, a, 32)
	}
	if t.v6 == nil {
		return false
	}
	return trieWalk(t.v6, a, 128)
}

func trieWalk(root *ipNode, a netip.Addr, max int) bool {
	n := root
	if n.end {
		return true
	}
	for i := 0; i < max; i++ {
		if n.next[bitAt(a, i)] == nil {
			return false
		}
		n = n.next[bitAt(a, i)]
		if n.end {
			return true
		}
	}
	return n.end
}

// ContainsIP is a convenience wrapper for net.IP (gopacket packet path).
func (b *IPBlocklistModule) ContainsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return b.Contains(a)
}

// Add inserts a canonicalized entry and persists it
func (b *IPBlocklistModule) Add(address string) error {
	p, err := parseIPPrefix(address)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, e := range b.entries {
		if e == p {
			return nil
		}
	}
	if len(b.entries) >= MaxIPBlocklistEntries {
		b.overflow.Add(1)
		return ErrIPBlocklistFull
	}
	if b.store != nil {
		if err := b.store.AddDynamicIP(p.String()); err != nil {
			return err
		}
	}
	b.entries = append(b.entries, p)
	b.rebuildLocked()
	return nil
}

// Remove deletes an entry
func (b *IPBlocklistModule) Remove(address string) error {
	p, err := parseIPPrefix(address)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for i, e := range b.entries {
		if e == p {
			b.entries = append(b.entries[:i], b.entries[i+1:]...)
			break
		}
	}
	if b.store != nil {
		if err := b.store.RemoveDynamicIP(p.String()); err != nil {
			return err
		}
	}
	b.rebuildLocked()
	return nil
}

// List returns a copy of the current entries as canonical strings
func (b *IPBlocklistModule) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.entries))
	for _, p := range b.entries {
		out = append(out, p.String())
	}
	return out
}

// Count returns the number of entries
func (b *IPBlocklistModule) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

// Overflow returns how many adds were rejected at capcity
func (b *IPBlocklistModule) Overflow() uint64 {
	return b.overflow.Load()
}

func (b *IPBlocklistModule) rebuildLocked() {
	t := &ipTire{}
	for _, p := range b.entries {
		t.insert(p)
	}
	b.trie.Store(t)
}
