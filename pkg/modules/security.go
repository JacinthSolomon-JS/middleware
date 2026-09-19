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

// DGA Detection Module
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
	fmt.Println(">>> EntropyModule Inspect() CALLED <<<")

	domain := strings.TrimSuffix(tctx.Domain, ".")

	parts := strings.Split(domain, ".")
	if len(parts) == 0 || parts[0] == "" {
		return false, nil
	}

	subdomain := parts[0]

	score := calculateDGAScore(subdomain, e.threshold)

	fmt.Printf("[DGA] %s | score=%d\n", subdomain, score)

	if score >= 4 {
		tctx.FinalAction = pipeline.ActionBlock
		tctx.MatchedBy = e.Name()
		tctx.BlockReason = fmt.Sprintf(
			"Suspicious DGA characteristics detected in '%s' (score=%d)",
			subdomain,
			score,
		)
	}

	return false, nil
}

func calculateDGAScore(s string, entropyThreshold float64) int {
	if len(s) == 0 {
		return 0
	}

	score := 0

	// Feature 1: Entropy
	entropy := calculateEntropy(s)

	if entropy >= entropyThreshold-0.4 {
		score += 2
	}

	// Feature 2: Length
	if len(s) >= 15 {
		score++
	}

	// Feature 3: Digit ratio
	digitCount := 0

	for _, char := range s {
		if char >= '0' && char <= '9' {
			digitCount++
		}
	}

	digitRatio := float64(digitCount) / float64(len(s))

	if digitRatio >= 0.25 {
		score++
	}

	// Feature 4: Character diversity
	unique := make(map[rune]bool)

	for _, char := range s {
		unique[char] = true
	}

	uniqueRatio := float64(len(unique)) / float64(len(s))

	if uniqueRatio >= 0.70 {
		score++
	}

	return score
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
