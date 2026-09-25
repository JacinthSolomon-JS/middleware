package modules

import (
	"context"
	"fmt"
	"math"
	"middleware/pkg/pipeline"
	"strings"
	"sync"
)

// Static Blocklist Midule
type BlocklistModule struct {
	mu      sync.RWMutex
	blocked map[string]bool
}

func NewBlocklistModule(domains []string) *BlocklistModule {
	m := make(map[string]bool)
	for _, d := range domains {
		m[strings.ToLower(strings.TrimSuffix(d, "."))] = true
	}
	return &BlocklistModule{blocked: m}
}

func (b *BlocklistModule) Name() string { return "StaticBlocklist" }

func (b *BlocklistModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	cleanDomain := strings.ToLower(strings.TrimSuffix(tctx.Domain, "."))

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.blocked[cleanDomain] {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = b.Name()
		tctx.BlockReason = fmt.Sprintf("Domain '%s' found in blocklist", cleanDomain)
	}
	return false, nil
}

// DGA Shannon Entropy Module
type EntropyModule struct {
	threshold float64
	logOnly   bool
}

func NewEntropyModule(threshold float64) *EntropyModule {
	return &EntropyModule{threshold: threshold, logOnly: true}
}

// NewEntropyModuleEnforcing is the opt in variant
func NewEntropyModuleEnforcing(threshold float64) *EntropyModule {
	return &EntropyModule{threshold: threshold}
}

// SetLogOnly flips the module between observe-only (default) and enforced)
func (e *EntropyModule) SetLogOnly(logOnly bool) { e.logOnly = logOnly }

func (e *EntropyModule) Name() string {
	return "EntropyDGA"
}

func (e *EntropyModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	domainStr := strings.TrimSpace(strings.TrimSuffix(tctx.Domain, "."))
	if domainStr == "" {
		return false, nil
	}

	label := dgaScoredLabel(domainStr)
	if label == "" {
		return false, nil
	}

	// Tightened constraints : entropy threshold + length check + mixed
	entropy := calculateEntropy(label)
	if entropy > e.threshold && len(label) > 12 && hasDigitsAndLetters(label) {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = e.Name()
		if e.logOnly {
			tctx.Monitor = true
			tctx.BlockReason = fmt.Sprintf("DGA suspicion (entropy %.2f > %.2f) on label %q - logOnly", entropy, e.threshold, label)
		} else {
			tctx.BlockReason = fmt.Sprintf("DGA suspicion (entropy %.2f > %.2f) on label %q", entropy, e.threshold, label)
		}
		return false, nil
	}
	return false, nil
}

// dgaScoredLabel returns the label and the heuristic scores
func dgaScoredLabel(domain string) string {
	labels := strings.Split(domain, ".")
	n := len(labels)
	switch {
	case n >= 2:
		return labels[n-2]
	case n == 1:
		return labels[0]
	}
	return ""
}

func hasDigitsAndLetters(s string) bool {
	hasDigit, hasLetter := false, false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
		}
		if hasDigit && hasLetter {
			return true
		}
	}
	return false
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
