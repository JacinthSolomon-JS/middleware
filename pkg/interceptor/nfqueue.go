package interceptor

import (
	"context"
	"fmt"
	"log"
	"middleware/pkg/pipeline"
	"middleware/pkg/storage"
	"net"
	"time"

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
		dedupe:    newBlockDedupe(DedupeWindow),
	}
}

// SetSampler installs the allowed-traffic sampler
func (h *NFQueueHandler) SetSampler(s *storage.Sampler) {
	h.sampler = s
}

// SetIPBlocklist installs the runtime malicious IP matcher
func (h *NFQueueHandler) SetIPBlocklist(m IPMatcher) {
	h.ipBlocklist = m
}

// HandlePacket processes incoming NFQUEUE attributes and issues verdicts
func (h *NFQueueHandler) HandlePacket(nf verdictSetter, a nfqueue.Attribute) int {
	if a.PacketID == nil {
		return 0
	}

	id := *a.PacketID
	settled := false
	settle := func(v int) {
		if settled {
			return
		}
		settled = true
		_ = nf.SetVerdict(id, v)
	}

	// A panic must never leave the packet unresolved
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[NFQUEUE] panic in handler for packet %d; accepting: %v", id, r)
			settle(nfqueue.NfAccept)
		}
	}()

	if a.Payload == nil {
		settle(nfqueue.NfAccept)
		return 0
	}
	payload := *a.Payload
	if len(payload) == 0 {
		settle(nfqueue.NfAccept)
		return 0
	}

	// Parse the raw IP packet to extract srcIP, dstIP and the TLS/SNI domain.
	var ipLayerType gopacket.LayerType
	if len(payload) > 0 && payload[0]>>4 == 6 {
		ipLayerType = layers.LayerTypeIPv6
	} else {
		ipLayerType = layers.LayerTypeIPv4
	}
	packet := gopacket.NewPacket(payload, ipLayerType, gopacket.Default)

	var srcIP, dstIP net.IP
	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		if ipv4, ok := ip4.(*layers.IPv4); ok {
			srcIP = ipv4.SrcIP
			dstIP = ipv4.DstIP
		}
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		if ipv6, ok := ip6.(*layers.IPv6); ok {
			srcIP = ipv6.SrcIP
			dstIP = ipv6.DstIP
		}
	}
	if srcIP == nil {
		srcIP = net.ParseIP("0.0.0.0")
	}

	// Direct-IP block: drop every packet to a blocked destination
	if h.ipBlocklist != nil && dstIP != nil && h.ipBlocklist.ContainsIP(dstIP) {
		verdict := nfqueue.NfDrop
		if h.Engine != nil && h.Engine.Monitor() {
			verdict = nfqueue.NfAccept
		}
		settle(verdict)
		if h.dedupe == nil || h.dedupe.emittable("", "ip:"+dstIP.String()) {
			h.record(storage.LogEvent{
				Timestamp:   time.Now(),
				Protocol:    "IP",
				ClientIP:    srcIP.String(),
				Target:      dstIP.String(),
				Action:      pipeline.ActionBlock.String(),
				BlockReason: "destination IP " + dstIP.String() + " matched IP blocklist",
				MatchedBy:   "IPBlocklist",
			})
		}
		return 0
	}

	tctx := pipeline.NewTrafficContext(
		fmt.Sprintf("pkt-%d", id),
		srcIP,
		"",
		0,
	)
	tctx.DstIP = dstIP

	domain, err := h.extractDomainFromPayload(packet)
	if err == nil && domain != "" {
		tctx.Domain = domain
		h.Engine.Process(context.Background(), tctx)

		if tctx.EnforcedAction() == pipeline.ActionBlock {
			if h.dedupe == nil || h.dedupe.emittable(dstIP.String(), domain) {
				h.record(storage.LogEvent{
					Timestamp:   time.Now(),
					Protocol:    "TLS",
					ClientIP:    tctx.SrcIP.String(),
					Target:      tctx.Domain,
					Action:      tctx.FinalAction.String(),
					BlockReason: tctx.BlockReason,
					MatchedBy:   tctx.MatchedBy,
				})
			}
			log.Printf("[BLOCK TLS] Drop stream for SNI domain: %s (%s)", domain, tctx.BlockReason)
			settle(nfqueue.NfDrop)
			return 0
		}

		// Allowed (or observed in monitor mode): record every occurrence.
		h.record(storage.LogEvent{
			Timestamp:   time.Now(),
			Protocol:    "TLS",
			ClientIP:    tctx.SrcIP.String(),
			Target:      tctx.Domain,
			Action:      tctx.FinalAction.String(),
			BlockReason: tctx.BlockReason,
			MatchedBy:   tctx.MatchedBy,
		})
	}

	settle(nfqueue.NfAccept)
	return 0
}

// record feeds an event to persistent log
func (h *NFQueueHandler) record(e storage.LogEvent) {
	if h.sampler != nil && !h.sampler.ShouldRecord(e.Action) {
		return
	}
	if h.db != nil {
		h.db.Log(e)
	}
	if h.events != nil {
		h.events.Broadcast(e)
	}
}

// Helper method to pull SNI or Host header out of the packet
func (h *NFQueueHandler) extractDomainFromPayload(packet gopacket.Packet) (string, error) {
	if h.Inspector == nil {
		return "", fmt.Errorf("inspector not initialised")
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", fmt.Errorf("no TCP layer")
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || tcp == nil {
		return "", fmt.Errorf("invalid TCP layer")
	}
	if !IsTLSClientHello(tcp.Payload) {
		return "", fmt.Errorf("not a TLS Client Hello")
	}
	return ExtractTLSSNI(tcp.Payload)
}
