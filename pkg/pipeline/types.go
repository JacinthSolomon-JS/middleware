package pipeline

import (
	"context"
	"net"
	"strings"
	"time"
)

type Action int

const (
	ActionAllow Action = iota
	ActionBlock
)

func (a Action) String() string {
	if a == ActionBlock {
		return "BLOCK"
	}
	return "ALLOW"
}

type TrafficContext struct {
	ID        string
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	Domain    string
	QType     uint16

	FinalAction Action
	BlockReason string
	MatchedBy   string
	Monitor     bool
}

// EnforcedAction is the action decision points (DNS response, packet verdict) and the logged event keeps,
// FinalAction so monitor captures what would have been blocked.
func (t *TrafficContext) EnforcedAction() Action {
	if t.Monitor && t.FinalAction == ActionAllow {
		return ActionAllow
	}
	return t.FinalAction
}

func NewTrafficContext(id string, srcIP net.IP, domain string, qType uint16) *TrafficContext {
	return &TrafficContext{
		ID:          id,
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		Domain:      domain,
		QType:       qType,
		FinalAction: ActionAllow,
	}
}

type SecurityModule interface {
	Name() string
	Inspect(ctx context.Context, tctx *TrafficContext) (stopPipeline bool, err error)
}

// SanitizeDomain makes a wire-supplied name safe to log, store, and display.
// Returns "" for anything hostile so callers can treat is as "no domain".
func SanitizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	if s == "" || len(s) > 253 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '-' || c == '.' || c == '_':
		default:
			return ""
		}
	}
	return s
}
