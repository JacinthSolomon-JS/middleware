package modules

import (
	"context"
	"testing"

	"middleware/pkg/pipeline"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0,
		},
		{
			name:     "same characters",
			input:    "aaaaaaaa",
			expected: 0,
		},
		{
			name:     "two different characters",
			input:    "abababab",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateEntropy(tt.input)

			if result != tt.expected {
				t.Errorf(
					"calculateEntropy(%q) = %f, expected %f",
					tt.input,
					result,
					tt.expected,
				)
			}
		})
	}
}
func TestBlocklistModule(t *testing.T) {
	blocklist := NewBlocklistModule([]string{
		"malware.com",
		"phishing-site.net",
	})

	tctx := pipeline.NewTrafficContext(
		"DNS-REQ",
		nil,
		"malware.com",
		1,
	)

	_, err := blocklist.Inspect(context.TODO(), tctx)

	if err != nil {
		t.Fatalf("Inspect returned an error: %v", err)
	}

	if tctx.FinalAction != pipeline.ActionBlock {
		t.Errorf("expected domain to be BLOCKED, got %s", tctx.FinalAction)
	}
}
func TestEntropyModule(t *testing.T) {
	entropyModule := NewEntropyModule(3.8)

	tctx := pipeline.NewTrafficContext(
		"DNS-REQ",
		nil,
		"x89a1zq98lbz19q7m3.biz",
		1,
	)

	_, err := entropyModule.Inspect(context.TODO(), tctx)

	if err != nil {
		t.Fatalf("Inspect returned an error: %v", err)
	}

	if tctx.FinalAction != pipeline.ActionBlock {
		t.Errorf(
			"expected domain to be BLOCKED, got %s",
			tctx.FinalAction,
		)
	}
}
func TestDGADomainEntropy(t *testing.T) {
	domain := "x89a1zq98lbz19q7m3"

	entropy := calculateEntropy(domain)

	t.Logf("Domain: %s", domain)
	t.Logf("Length: %d", len(domain))
	t.Logf("Entropy: %.4f", entropy)
	t.Logf("Threshold: %.1f", 3.8)

	if entropy > 3.8 {
		t.Log("Result: would be BLOCKED")
	} else {
		t.Log("Result: would be ALLOWED")
	}
}
func TestLegitimateDomains(t *testing.T) {
	module := NewEntropyModule(3.8)

	domains := []string{
		"google.com",
		"microsoft.com",
		"amazon.com",
		"github.com",
		"cloudflare.com",
		"stackoverflow.com",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			tctx := pipeline.NewTrafficContext(
				"DNS-REQ",
				nil,
				domain,
				1,
			)

			_, err := module.Inspect(context.TODO(), tctx)

			if err != nil {
				t.Fatalf("Inspect returned an error: %v", err)
			}

			if tctx.FinalAction == pipeline.ActionBlock {
				t.Errorf(
					"legitimate domain %q was BLOCKED: %s",
					domain,
					tctx.BlockReason,
				)
			}
		})
	}
}
