package interceptor

import (
	"context"
	"fmt"
	"middleware/pkg/pipeline"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketInspector struct {
	engine *pipeline.Engine
}

func NewPacketInspector(engine *pipeline.Engine) *PacketInspector {
	return &PacketInspector{engine: engine}
}

func (pi *PacketInspector) InspectPacket(rawPacket []byte) (pipeline.Action, string) {
	if len(rawPacket) == 0 {
		return pipeline.ActionAllow, ""
	}

	var ipLayerType gopacket.LayerType
	var srcIP net.IP
	var dstIP net.IP

	version := rawPacket[0] >> 4
	if version == 4 {
		ipLayerType = layers.LayerTypeIPv4
	} else if version == 6 {
		ipLayerType = layers.LayerTypeIPv6
	} else {
		return pipeline.ActionAllow, ""
	}

	packet := gopacket.NewPacket(rawPacket, ipLayerType, gopacket.Default)
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

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return pipeline.ActionAllow, ""
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || tcp == nil {
		return pipeline.ActionAllow, ""
	}

	if tcp.DstPort != 443 {
		return pipeline.ActionAllow, ""
	}

	payload := tcp.Payload
	if len(payload) == 0 {
		return pipeline.ActionAllow, ""
	}

	if IsTLSClientHello(payload) {
		sni, err := ExtractTLSSNI(payload)
		if err == nil && sni != "" {
			tctx := pipeline.NewTrafficContext(
				fmt.Sprintf("TCP-%d", tcp.SrcPort),
				srcIP,
				sni,
				0,
			)

			pi.engine.Process(context.Background(), tctx)

			if tctx.FinalAction == pipeline.ActionBlock {
				fmt.Printf("[DROP] Connection to %s (%s:443) dropped! Reason: %s\n",
					sni, dstIP, tctx.BlockReason)
				return pipeline.ActionBlock, sni
			}

			fmt.Printf("[ACCEPT] Connection to %s (%s:443) allowed.\n", sni, dstIP)
			return pipeline.ActionAllow, sni
		}
	}
	return pipeline.ActionAllow, ""
}
