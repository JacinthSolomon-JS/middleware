package main

import (
	"context"
	"fmt"
	"log"
	"middleware/pkg/dns"
	"middleware/pkg/interceptor"
	"middleware/pkg/modules"
	"middleware/pkg/pipeline"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/florianl/go-nfqueue"
)

func main() {
	fmt.Println("Starting Gateway Resolver...")

	// Initialize Pipeline & Engine Setup
	engine := pipeline.NewEngine()
	blocklist := modules.NewBlocklistModule([]string{
		"malware.com",
		"phishing-site.net",
		"ads.doubleclick.net",
	})
	engine.RegisterModule(blocklist)

	entropyDetector := modules.NewEntropyModule(3.2)
	engine.RegisterModule(entropyDetector)

	// Initialize Inspector & Handler Simulated Testing
	inspector := interceptor.NewPacketInspector(engine)
	handler := interceptor.NewNFQueueHandler(engine, inspector)

	// Initialize Simulated Testing
	fmt.Println("\nTesting: TLS SNI Packet Extraction")
	testSimulatedTLSPackets()

	// DNS Resolver Server Setup
	fmt.Println("\nStarting Local DNS Resolver on UDP 127.0.0.1:1053")
	dnsServer := dns.NewServer("127.0.0.1:1053", "1.1.1.1:53", engine)
	go func() {
		if err := dnsServer.Start(); err != nil {

			log.Printf("DNS Server failed to start: %v", err)
		}
	}()

	// Setup Signal Handling & Context for Graceful Shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChain := make(chan os.Signal, 1)
	signal.Notify(sigChain, syscall.SIGINT, syscall.SIGTERM)

	// Configure IPTables Rules
	setupIptables()
	defer cleanupIptables()

	// NFQUEUE Initialization
	fmt.Println("\nAttempting to connect to NFQUEUE Number 0...")
	config := nfqueue.Config{
		NfQueue:      0,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Fatalf("Could not open NFQUEUE: %v", err)
	}
	defer func(nf *nfqueue.Nfqueue) {
		err := nf.Close()
		if err != nil {

		}
	}(nf)

	nfHook := func(a nfqueue.Attribute) int {
		return handler.HandlePacket(nf, a)
	}

	if err := nf.Register(ctx, nfHook); err != nil {
		log.Fatalf("Failed to register nfqueue: %v", err)
	}

	fmt.Println("Successfully connected to NFQUEUE!")
	fmt.Println("\nWaiting for packets... (Press Ctrl+C to stop)")

	// Wait for Shutdown Signal
	<-sigChain
	fmt.Println("\nShutting down Gateway...")
}

// Setting up IPTables
func setupIptables() {
	fmt.Println("\nSetting up IPTables...")
	cmd := exec.Command("iptables", "-A", "OUTPUT")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("[ERROR] IPTables failed: %v", err)
	}
}

// IPTables Cleaner
func cleanupIptables() {
	fmt.Println("\nCleaning up IPTables... Restoring normal internet.")
	cmd := exec.Command("iptables", "-D", "OUTPUT", "-p", "icmp", "-j", "NFQUEUE", "--queue-num", "0")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("[ERROR] IPTables not cleared: %v", err)
	}
}

// Simulated test to check SNI Inspection, Static Block and DGA Entropy.
func testSimulatedTLSPackets() {
	fmt.Println("\nStarting Simulated Testing....")

	tctx := pipeline.NewTrafficContext("Test-01", nil, "bad-ip-domain.org", 0)
	engine := pipeline.NewEngine()
	engine.RegisterModule(modules.NewBlocklistModule([]string{"bad-ip-domain.org"}))

	fmt.Printf("SNI inspection for domain: %s.. \n", tctx.Domain)
	engine.Process(nil, tctx)
	fmt.Printf("Result: Action:%s, Reason:%s\n", tctx.FinalAction, tctx.BlockReason)

	dgaDomain := "x89a1zq98lbz19q7m3.biz"
	tctxDGA := pipeline.NewTrafficContext("Test-02", nil, dgaDomain, 0)
	engine.RegisterModule(modules.NewEntropyModule(3.2))

	fmt.Printf("Simulating SNI inspection for DGA domain: %s..\n", dgaDomain)
	engine.Process(nil, tctxDGA)
	fmt.Printf("Result: Action:%s, Reason:%s\n", tctxDGA.FinalAction, tctxDGA.BlockReason)
}
