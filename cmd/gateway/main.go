package main

import (
	"fmt"
	"log"

	"middleware/pkg/interceptor"

	"middleware/pkg/dns"
	"middleware/pkg/modules"
	"middleware/pkg/pipeline"
)

func main() {
	fmt.Println("Starting Gateway Resolver")

	engine := pipeline.NewEngine()

	blocklist := modules.NewBlocklistModule([]string{
		"malware.com",
		"phishing-site.net",
		"ads.doubleclick.net",
	})

	engine.RegisterModule(blocklist)

	entropyDetector := modules.NewEntropyModule(3.2)
	engine.RegisterModule(entropyDetector)

	inspector := interceptor.NewPacketInspector(engine)

	fmt.Println("Testing: TLS SNI Packet Extraction")
	testSimulatedTLSPackets(inspector)

	fmt.Println("Starting Local DNS Resolver on UDP 127.0.0.1:1053")
	dnsServer := dns.NewServer("127.0.0.1:1053", "1.1.1.1:53", engine)

	if err := dnsServer.Start(); err != nil {
		log.Fatalf("DNS Server failed to start: %v", err)
	}
}

func testSimulatedTLSPackets(inspector *interceptor.PacketInspector) {
	tctx := pipeline.NewTrafficContext("Test-01", nil, "bad-ip-domain.org", 0)
	engine := pipeline.NewEngine()
	engine.RegisterModule(modules.NewBlocklistModule([]string{"bad-ip-domain.org"}))

	fmt.Printf("SNI inspection for domain: %s.. \n", tctx.Domain)
	engine.Process(nil, tctx)
	fmt.Printf("Result: Action:%s, Reason:%s\n", tctx.FinalAction, tctx.BlockReason)

	dgaDomain := "x89a1zq98lbz19q7m3.biz"
	tctxDGA := pipeline.NewTrafficContext("Test-02", nil, dgaDomain, 0)
<<<<<<< HEAD
	engine.RegisterModule(modules.NewEntropyModule(3.2))
=======
	engine.RegisterModule(modules.NewEntropyModule(3.8))
>>>>>>> 1ad61f0917d4437931370f3ee94a5fdfab9a011b

	fmt.Printf("Simulating SNI inspection for DGA domain: %s..\n", dgaDomain)
	engine.Process(nil, tctxDGA)
	fmt.Printf("Result: Action:%s, Reason:%s\n", tctxDGA.FinalAction, tctxDGA.BlockReason)
}
