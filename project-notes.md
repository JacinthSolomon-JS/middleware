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

#### Architecture Overview
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

#### Test Trials

##### Test 1
```Bash
go run cmd/gateway/main.go # Run the middleware with port 1053
dig @127.0.0.1 -p 1053 google.com # Normal Domain resolve to 1.1.1.1 (cloudflare)
dig @127.0.0.1 -p 1053 malware.com # Static Blocklist Domain (Sink-hole to 0.0.0.0)
dig @127.0.0.1 -p 1053 x89a1zq98lbz19q7m3.biz # Zero-Day DGA Domain (High Entropy - Should BLOCK) {Didn't work}
```
The DGA High-Entropy Domain didn't work and did not BLOCK the domain.
