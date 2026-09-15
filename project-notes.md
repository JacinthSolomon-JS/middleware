## Initial Dev Setup 

```bash
mkdir -p middleware\{cmd/gateway,config,pkg/api,pkg/dns,pkg/interceptor,pkg/modules,pkg/pipeline,pkg/storage}
cd middleware
go mod init middleware
```
#### Imported Dependencies
```bash
go get github.com/miekg/dns  # Wire-format DNS parser & server.
go get github.com/google/gopacket # Packet parsing (TLS SNI extraction). 
go get github.com/mattn/go-sqlite3 # Embedded metrics & log.
go get github.com/florianl/go-nfqueue/v2 # Linux NFQUEUE userspace binding.
go get github.com/gorilla/websocket # WebSocket upgrader and live client connection managment for real time.
go get github.com/gin-gonic/gin # High-Performance REST API routing.
```

#### Configuring Linux Kernel to Forwording & IP Setup
```bash
# Enable forwarding in runtime
sudo sysctl -w net.ipv4.ip_forward=1

# Persists across reboot
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

---
## Notes

1.  **[SOLVED]** Common Errors for initializing IP-Tables ``` [ERROR] IPTables failed: exec: "iptables": executable file not found in $PATH ``` 
    - Install iptables via system packet manager  
      ```bash
      # Debian/Ubuntu/Kali
      sudo apt update && sudo apt install -y iptables
      
      # Arch based
      sudo pacman -S iptables
      
      # RHEL/CentOS/Fedora
      sudo dnf install iptables-services iptables
      ```
    - Run with Root Privileges 
      ```bash
      # Elevated Root Privileges
      sudo go run . 
      # or use  compiled binary
      sudo go build main.go && sudo ./main      
      ```
---
### Architecture Overview
```plaintext
[ Client Application ] ──(TCP :443 TLS Handshake)──> [ Linux Kernel NFQUEUE ]
                                                             │
                                                             ▼
                                                    [ Go Interceptor ]
                                                             │
                                                  1. Parse TCP & TLS Client Hello
                                                  2. Extract SNI (e.g. "malware.com")
                                                             │
                                                             ▼
                                                    [ Pipeline Engine ]
                                                   (Blocklist / DGA Check)
                                                             │
                                                             ▼
                                                Verdict: NF_ACCEPT or NF_DROP
```

#### Traffic Flow
```plaintext
[ LAN Client Device ]
    │ (Gateway IP: 192.168.1.1)
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Linux Hardware Gateway / VM                                 │
│                                                             │
│  1. Forwarding Kernel Flag: net.ipv4.ip_forward = 1         │
│  2. nftables Rules:                                         │
│     • UDP 53  ──> Redirect to Go Local DNS (:1053)          │
│     • TCP 443 ──> Queue to NFQUEUE (num 0)                  │
│                                                             │
│  3. Go Middleware Process:                                  │
│     • Listens on NFQUEUE 0 via libnetfilter_queue           │
│     • Parses TLS SNI ClientHello                            │
│     • Verdict: NF_ACCEPT (Forward) or NF_DROP (Block)       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
                       [ WAN / Internet ]
```

#### Storage Architecture
```plaintext
               ┌───────────────────────────────────────────────┐
               │    Pipeline Engine (DNS / SNI Inspector)      │
               └───────────────────────┬───────────────────────┘
                                       │ (Async Log Event)
                                       ▼
                       ┌───────────────────────────────┐
                       │   Buffered Channel (10,000)   │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │  Batch Worker Thread (Go)     │
                       │  (Flushes every 2s or 100 logs) │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   Embedded SQLite Database    │
                       └───────────────────────────────┘
```

#### Web Dashboard and Real time WebSocket with Storage
```plaintext
                               ┌──────────────────────────────────┐
                               │   Go Gateway Daemon              │
                               │                                  │
┌────────────────────┐         │   ┌──────────────────────────┐   │
│ Web Dashboard      │ ──REST──┼──>│  Gin HTTP API Router     │   │
│ (React / VanillaJS)│ <──WS───┼───┤  WebSocket Hub           │   │
└────────────────────┘         │   └────────────┬─────────────┘   │
                               │                │                 │
                               │                ▼                 │
                               │   ┌──────────────────────────┐   │
                               │   │ SQLite Storage Engine    │   │
                               │   └──────────────────────────┘   │
                               └──────────────────────────────────┘
```
### Test Trials

##### Test 1
```Bash
go run cmd/gateway/main.go # Run the middleware with port 1053
dig @127.0.0.1 -p 1053 google.com # Normal Domain resolve to 1.1.1.1 (cloudflare)
dig @127.0.0.1 -p 1053 malware.com # Static Blocklist Domain (Sink-hole to 0.0.0.0)
dig @127.0.0.1 -p 1053 x89a1zq98lbz19q7m3.biz # Zero-Day DGA Domain (High Entropy - Should BLOCK) {Didn't work}
```

Now DGA High-Entropy Domain work.
