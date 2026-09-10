package interceptor

import (
	"context"
	"fmt"
	"middleware/pkg/pipeline"

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
	packet := gopacket.NewPacket(rawPacket, layers.LayerTypeIPv4, gopacket.Default)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return pipeline.ActionAllow, ""
	}
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return pipeline.ActionAllow, ""
	}
	tcp, _ := tcpLayer.(*layers.TCP)

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
				ip.SrcIP,
				sni,
				0,
			)

			pi.engine.Process(context.Background(), tctx)

			if tctx.FinalAction == pipeline.ActionBlock {
				fmt.Printf("[DROP] Connection to %s (%s:443) dropped! Reason: %s\n",
					sni, ip.DstIP, tctx.BlockReason)
				return pipeline.ActionBlock, sni
			}

			fmt.Printf("[ACCEPT] Connection to %s (%s:443) allowed.\n", sni, ip.DstIP)
			return pipeline.ActionAllow, sni
		}
	}
	return pipeline.ActionAllow, ""
}
