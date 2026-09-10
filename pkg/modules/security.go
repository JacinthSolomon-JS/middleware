package modules

import (
	"context"
	"fmt"
	"math"
	"middleware/pkg/pipeline"
	"strings"
)

// Static Blocklist Midule
type BlocklistModule struct {
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
}

func NewEntropyModule(threshold float64) *EntropyModule {
	return &EntropyModule{threshold: threshold}
}

func (e *EntropyModule) Name() string {
	return "EntropyDGA"
}

func (e *EntropyModule) Inspect(ctx context.Context, tctx *pipeline.TrafficContext) (bool, error) {
	parts := strings.Split(strings.TrimSuffix(tctx.Domain, "."), ".")
	if len(parts) == 0 {
		return false, nil
	}
	subdomain := parts[0]

	entropy := calculateEntropy(subdomain)
	if entropy > e.threshold && len(subdomain) > 8 {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = e.Name()
		tctx.BlockReason = fmt.Sprintf("High entropy (%.2f > %.2f) detected on '%s'", entropy, e.threshold, subdomain)
		return false, nil
	}
	return false, nil
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, char := range s {
		counts[char]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
