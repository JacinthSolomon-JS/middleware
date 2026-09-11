package main

import (
	"fmt"
	"log"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"middleware/pkg/interceptor"

	"middleware/pkg/dns"
	"middleware/pkg/modules"
	"middleware/pkg/pipeline"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"          // 💡 NAYA: Raw data ko packet banane ke liye
	"github.com/google/gopacket/layers"  // 💡 NAYA: IPv4 aur ICMP layers ko padhne ke liye
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


	// server gorutine mai chal raha hai - Path A, aur ye requests ko sunega or jo packets hai wo path B se hoke jayenge
	go func() {
		if err := dnsServer.Start(); err != nil {
			log.Printf("DNS Server failed to start: %v", err)
		}
	}()

	fmt.Println("🚀 RouteSec Gateway Starting...")

	// Jaise hi program chale, sabse pehle Step 1 (Trap) automate karo
	setupIptables()

	// 'defer' ka matlab hai ki jab bhi program band hoga (chahe error aaye ya Ctrl+C dabe), ye cleanup zaroor chalega
	defer cleanupIptables()

	fmt.Println("Attempting to connect to NFQUEUE Number 0...")

	config := nfqueue.Config{
		NfQueue:      0,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Fatalf("❌ Could not open NFQUEUE: %v", err)
	}
	defer nf.Close()













	////////////////////////////////////////////////////////////////////////////////////////////////

	// ye path B hai jo ki main line hai janha se packet par kaam hoga
	// Callback Function (Full ICMP Decoding)
	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		payload := *a.Payload

		// Raw bytes ko packet mein badalna
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

		fmt.Printf("\n--- 📦 Naya Packet Aaya (ID: %d) ---\n", id)

		// 1. IP Layer Extract Karna
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("🌐 IPv4 Layer : Source: %s ---> Dest: %s\n", ip.SrcIP, ip.DstIP)
		}

		// 2. ICMP Layer Extract Karna (Ping ki asli details)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)

			// ICMP Type 8 = Echo Request (Ping bhejna)
			// ICMP Type 0 = Echo Reply (Jawab aana)
			msgType := "Unknown"
			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
				msgType = "Echo Request (Ping Gaya ↗️)"
			} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
				msgType = "Echo Reply (Jawab Aaya ↙️)"
			}

			fmt.Printf("🔨 ICMP Layer : Type: %s | Seq: %d\n", msgType, icmp.Seq)
		} else {
			fmt.Println("⚠️ Ye ICMP packet nahi hai!")
		}

		// Packet ko aage jaane ki permission dena (Accept)
		err := nf.SetVerdict(id, nfqueue.NfAccept)
		if err != nil {
			log.Printf("Error setting verdict: %v\n", err)
		}
		return 0
	}
	///////////////////////////////////////////////////////////////////////////////////////////










	err = nf.Register(context.Background(), fn)
	if err != nil {
		log.Fatalf("❌ Failed to register nfqueue: %v", err)
	}

	fmt.Println("✅ Successfully connected to NFQUEUE!")
	fmt.Println("⏳ Waiting for packets... (Press Ctrl+C to stop)")

	// Program ko chalu rakhne ke liye aur Ctrl+C ka wait karne ke liye
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n🛑 Shutting down RouteSec Gateway...")
	// Yahan main function khatam hoga, aur automatically 'defer cleanupIptables()' chal jayega!
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
	engine.RegisterModule(modules.NewEntropyModule(3.2))

	fmt.Printf("Simulating SNI inspection for DGA domain: %s..\n", dgaDomain)
	engine.Process(nil, tctxDGA)
	fmt.Printf("Result: Action:%s, Reason:%s\n", tctxDGA.FinalAction, tctxDGA.BlockReason)
}

// Automate Step 1: Program start hote hi iptables rule lagana
func setupIptables() {
	fmt.Println("⚙️ Automating Step 1: Applying iptables rules...")
	// Abhi test ke liye ICMP (Ping) par laga rahe hain
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "NFQUEUE", "--queue-num", "0")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("❌ Failed to set iptables rule (Did you run with sudo?). Error: %v", err)
	}
}

// Program band hone par rule hatana taaki internet block na reh jaye
func cleanupIptables() {
	fmt.Println("\n🧹 Cleaning up iptables rules... Restoring normal internet.")
	// -A (Add) ki jagah -D (Delete) use kar rahe hain
	cmd := exec.Command("iptables", "-D", "OUTPUT", "-p", "icmp", "-j", "NFQUEUE", "--queue-num", "0")
	cmd.Run()
}
