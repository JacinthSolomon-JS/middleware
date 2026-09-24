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

####

1. **[SOLVED]** Common Errors for initializing IP-Tables
`[ERROR] IPTables failed: exec: "iptables": executable file not found in $PATH` 
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
  
2. Kernel-Level Packet Filtering with eBPF via XDP for Performance and Security is leveraging eBPF (Extended Berkeley Packet Filter) via XDP (eXpress Data Path) inside the Linux kernel.
    [Read More..](https://www.cerbos.dev/blog/20-open-source-tools-for-zero-trust-architecture#:~:text=*%20Encrypts%20traffic%20between%20workloads%20to%20protect,behaviour%2C%20assisting%20in%20monitoring%20and%20troubleshooting%20efforts.)
    
3. Native System Firewall with `iptables`/`nftables` can build a daemon that runs alongside standard Linux tools, Similar approach to Fail2ban or CrowdSec.
4. Inline Reverse Proxy/TLS SNI Inspector (OSI Layer 7 Deep Packet Inspectio)
---

#### Pre-Configured Blocklists
These are sample categorized pre-configured blocklists
```markdown
1. GENERAL ADBLOCKING & PRIVACY (10 Lists)

{"oisd-small", "OISD Small (Basic)", "General Adblocking & Privacy", "https://small.oisd.nl"},
{"oisd-big", "OISD Big (Comprehensive)", "General Adblocking & Privacy", "https://big.oisd.nl"},
{"steven-black", "StevenBlack Unified Hosts", "General Adblocking & Privacy", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
{"adguard-dns", "AdGuard DNS Main Filter", "General Adblocking & Privacy", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
{"adguard-base", "AdGuard Base Filter", "General Adblocking & Privacy", "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_English/filter.txt"},
{"adguard-mobile", "AdGuard Mobile Ads", "General Adblocking & Privacy", "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt"},
{"easylist", "EasyList Main", "General Adblocking & Privacy", "https://easylist.to/easylist/easylist.txt"},
{"easyprivacy", "EasyPrivacy Tracker Block", "General Adblocking & Privacy", "https://easylist.to/easylist/easyprivacy.txt"},
{"pgl-yoyo", "Peter Lowe's Ad & Tracking List", "General Adblocking & Privacy", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
{"duckduckgo-radar", "DuckDuckGo Tracker Radar", "General Adblocking & Privacy", "https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/domains/US.txt"},

2. SECURITY, MALWARE & PHISHING (12 Lists)

{"urlhaus", "URLHaus Malware Domains", "Security & Phishing", "https://urlhaus.abuse.ch/downloads/hostfile/"},
{"phisharmy", "PhishArmy Extended List", "Security & Phishing", "https://phish.army/download/phishing_army_blocklist_extended.txt"},
{"openphish", "OpenPhish Active Feed", "Security & Phishing", "https://openphish.com/feed.txt"},
{"malwaredomainlist", "MalwareDomainList Main", "Security & Phishing", "https://www.malwaredomainlist.com/hostslist/hosts.txt"},
{"threatfox", "ThreatFox IOC Malicious Domains", "Security & Phishing", "https://threatfox.abuse.ch/downloads/hostfile/"},
{"vxvault", "VX Vault URL List", "Security & Phishing", "http://vxvault.net/URL_List.php"},
{"scam-blocklist", "Malicious Scam Domains", "Security & Phishing", "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt"},
{"digitalside-threat", "DigitalSide Threat Intel OSINT", "Security & Phishing", "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"},
{"alienvault-reputation", "AlienVault IP/Domain Reputation", "Security & Phishing", "https://reputation.alienvault.com/reputation.data"},
{"cert-pl", "CERT Poland Warn List", "Security & Phishing", "https://cert.pl/posts/2020/03/ostrzezenia_phishing/list.txt"},
{"stamparm-ipsum", "IPsum Malicious Network Feed", "Security & Phishing", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"},
{"blocklist-de", "Blocklist.de Fail2Ban IPs", "Security & Phishing", "https://lists.blocklist.de/lists/all.txt"},

3. PARENTAL CONTROL & ADULT CONTENT (10 Lists)

{"steven-porn", "StevenBlack Porn Blocklist", "Parental Control & Adult", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"},
{"cleandns-adult", "CleanBrowsing Adult Filter", "Parental Control & Adult", "https://raw.githubusercontent.com/CleanBrowsing/dns-blocklists/master/adult-blocklist.txt"},
{"adguard-adult", "AdGuard Family Adult Filter", "Parental Control & Adult", "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/family.txt"},
{"nsfw-hosts", "NSFW Community Blocklist", "Parental Control & Adult", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts"},
{"big-daddys-porn", "Big Daddy's NSFW Blocklist", "Parental Control & Adult", "https://raw.githubusercontent.com/badmojc/127.0.0.1/master/porn"},
{"chadmayfield-adult", "Chad Mayfield Adult Blocklist", "Parental Control & Adult", "https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/AdultForPiHole.txt"},
{"oliver-adult", "Oliver Hough Adult List", "Parental Control & Adult", "https://raw.githubusercontent.com/oliverhough89/Adult-Block-List/master/hosts"},
{"blocklistproject-porn", "BlockList Project Adult", "Parental Control & Adult", "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt"},
{"steven-gambling", "StevenBlack Gambling Block", "Parental Control & Adult", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts"},
{"blocklistproject-gambling", "BlockList Project Gambling", "Parental Control & Adult", "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt"},

4. CRYPTOMINING & FRAUD (6 Lists)

{"coinblocker", "CoinBlockerLists Mining", "Cryptomining & Fraud", "https://raw.githubusercontent.com/Zerodot0/CoinBlockerLists/master/list.txt"},
{"no-coin", "NoCoin Cryptomining Filter", "Cryptomining & Fraud", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt"},
{"crypto-scamdb", "Crypto ScamDB Phishing/Scams", "Cryptomining & Fraud", "https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/out/hosts-format.txt"},
{"steven-crypto", "StevenBlack Crypto/Crypto-Jacking", "Cryptomining & Fraud", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"},
{"blocklistproject-crypto", "BlockList Project Crypto Domains", "Cryptomining & Fraud", "https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt"},
{"miner-gate", "In-Browser Miner Gateways", "Cryptomining & Fraud", "https://raw.githubusercontent.com/Energen/miner-blocklist/master/miners.txt"},

5. SOCIAL MEDIA TRACKING (6 Lists)

{"steven-social", "StevenBlack Social Media Block", "Social Media Tracking", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts"},
{"adguard-social", "AdGuard Social Media Filter", "Social Media Tracking", "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt"},
{"blocklistproject-facebook", "BlockList Project Facebook", "Social Media Tracking", "https://raw.githubusercontent.com/blocklistproject/Lists/master/facebook.txt"},
{"blocklistproject-twitter", "BlockList Project Twitter/X", "Social Media Tracking", "https://raw.githubusercontent.com/blocklistproject/Lists/master/twitter.txt"},
{"blocklistproject-tiktok", "BlockList Project TikTok", "Social Media Tracking", "https://raw.githubusercontent.com/blocklistproject/Lists/master/tiktok.txt"},
{"blocklistproject-youtube", "BlockList Project YouTube Trackers", "Social Media Tracking", "https://raw.githubusercontent.com/blocklistproject/Lists/master/youtube.txt"},

6. TELEMETRY & SMART DEVICES (6 Lists)

{"crazy-max-windows", "CrazyMax Windows Telemetry", "Telemetry & Smart Devices", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"},
{"smart-tv-telemetry", "Smart TV Telemetry (Samsung/LG/Roku)", "Telemetry & Smart Devices", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt"},
{"amazon-fire-telemetry", "Amazon FireTV Telemetry", "Telemetry & Smart Devices", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt"},
{"apple-telemetry", "Apple Telemetry Blocklist", "Telemetry & Smart Devices", "https://raw.githubusercontent.com/blocklistproject/Lists/master/apple.txt"},
{"telemetry-mobile", "Android / iOS OEM Telemetry", "Telemetry & Smart Devices", "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt"},
{"steven-fakenews", "StevenBlack Fake News Guard", "Telemetry & Smart Devices", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts"},
```

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
### Testing

```Bash
go run cmd/gateway/main.go # Run the middleware with port 1053
or 
sudo go run .

dig @127.0.0.1 -p 1053 google.com # Normal Domain resolve to 1.1.1.1 (cloudflare)
dig @127.0.0.1 -p 1053 malware.com # Static Blocklist Domain (Sink-hole to 0.0.0.0)
dig @127.0.0.1 -p 1053 x89a1zq98lbz19q7m3.biz # Zero-Day DGA Domain (High Entropy - Should BLOCK) {Didn't work}

dig @127.0.0.1 -p 1053 $(openssl rand -hex 8).com # Generates a random high-entropy 16-character string domain
```
