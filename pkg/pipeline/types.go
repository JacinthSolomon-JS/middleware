package pipeline

import (
	"context"
	"net"
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
	Domain    string
	QType     uint16

	FinalAction Action
	BlockReason string
	MatchedBy   string
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
