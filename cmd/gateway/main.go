package main

import (
	"fmt"
	"log"

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

	entropyDetector := modules.NewEntropyModule(3.8)
	engine.RegisterModule(entropyDetector)

	dnsServer := dns.NewServer("127.0.0.1:1053", "1.1.1.1:53", engine)

	if err := dnsServer.Start(); err != nil {
		log.Fatalf("DNS Server failed to start: %v", err)
	}
}
