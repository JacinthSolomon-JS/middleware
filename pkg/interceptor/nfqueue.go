package interceptor

import (
	"context"
	"fmt"
	"log"
	"middleware/pkg/pipeline"
	"middleware/pkg/storage"
	"net"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// verdictSetter lets tests substitute a fake for *nfqueue.Nfqueue
type verdictSetter interface {
	SetVerdict(id uint32, verdict int) error
}

// IPMatcher reports whether a destination IP is blocked by the runtime IP blocklist
type IPMatcher interface {
	ContainsIP(ip net.IP) bool
}

// NFQueueHandler holds references to our decision engine and inspector
type NFQueueHandler struct {
	Engine      *pipeline.Engine
	Inspector   *PacketInspector
	db          *storage.Database
	events      storage.EventSink
	ipBlocklist IPMatcher
	sampler     *storage.Sampler
	dedupe      *blockDedupe
}

func NewNFQueueHandler(engine *pipeline.Engine, inspector *PacketInspector, db *storage.Database, events storage.EventSink) *NFQueueHandler {
	return &NFQueueHandler{
		Engine:    engine,
		Inspector: inspector,
		db:        db,
		events:    events,
		dedupe:    newBlockDedupe(),
	}
}

// HandlePacket processes incoming NFQUEUE attributes and issues verdicts
func (h *NFQueueHandler) HandlePacket(nf *nfqueue.Nfqueue, a nfqueue.Attribute) int {
	if a.PacketID == nil || a.Payload == nil {
		return 0
	}

	id := *a.PacketID
	payload := *a.Payload

	// 1. Parse raw network layers
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

	var srcIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv4); ok {
			srcIP = ip.SrcIP
		}
	}

	// 2. Extract domain (SNI from TLS Client Hello or DNS Request Payload)
	extractedDomain := h.extractDomainFromPayload(packet)

	// 3. Build Traffic Context for the Pipeline
	tctx := pipeline.NewTrafficContext(
		fmt.Sprintf("pkt-%d", id),
		srcIP,
		extractedDomain,
		0,
	)

	// 4. Run packet context through the Pipeline Engine
	h.Engine.Process(context.Background(), tctx)

	// 5. Enforce verdict based on Pipeline Action
	verdict := nfqueue.NfAccept
	if tctx.FinalAction == pipeline.ActionBlock {
		verdict = nfqueue.NfDrop
		fmt.Printf("[BLOCKED] Packet ID: %d | Domain: %s | Reason: %s\n", id, tctx.Domain, tctx.BlockReason)
	} else {
		fmt.Printf("[ALLOWED] Packet ID: %d | Domain: %s\n", id, tctx.Domain)
	}

	// 6. Return Verdict to Kernel via NFQUEUE
	if err := nf.SetVerdict(id, verdict); err != nil {
		log.Printf("Error setting verdict for packet ID %d: %v\n", id, err)
	}

	return 0
}

// Helper method to pull SNI or Host header out of the packet
func (h *NFQueueHandler) extractDomainFromPayload(packet gopacket.Packet) string {
	if h.Inspector != nil {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if IsTLSClientHello(tcp.Payload) {
				sni, err := ExtractTLSSNI(tcp.Payload)
				if err == nil {
					return sni
				}
			}
		}
	}
	return ""
}
