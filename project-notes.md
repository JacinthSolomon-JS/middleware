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
<<<<<<< HEAD
                                                             ▼
=======
                                                             v
>>>>>>> 1ad61f0917d4437931370f3ee94a5fdfab9a011b
                                                    [ Go Interceptor ]
                                                             │
                                                  1. Parse TCP & TLS Client Hello
                                                  2. Extract SNI (e.g. "malware.com")
                                                             │
<<<<<<< HEAD
                                                             ▼
                                                    [ Pipeline Engine ]
                                                   (Blocklist / DGA Check)
                                                             │
                                                             ▼
                                                Verdict: NF_ACCEPT or NF_DROP
```

=======
                                                             v
                                                    [ Pipeline Engine ]
                                                   (Blocklist / DGA Check)
                                                             │
                                                             v
                                                Verdict: NF_ACCEPT or NF_DROP
```

#### Entropy Domain
##### Low Entropy Domains (Readable)
Entropy typically <3.0
```markdown
google.com
yahoo.com
microsoft.com
example.com
aaaaaaaaaa.com
```
##### Medium Entropy Domains (Longer Words and Subdomains)
```markdown
wikipedia.org
instagram.com
login.microsoftonline.com
appsync-api.us-east-1.avsvmcloud.com // Cloud/CDN patterns that sometimes trigger false positives in basic filters
```
##### High Entropy Domains (Random and Auto-Generated)
Entropy typically >3.5 to 4.5+
```markdown
x89a1zq98lbz19q7m3.biz
7x9q2m4k8p.com
kjhgfdsazx.com
q398rhflkjqwfg.com
sfqpit75pjh525siewar2dtgt5.com
zxcvbnmasdflkjgh.com
```

>>>>>>> 1ad61f0917d4437931370f3ee94a5fdfab9a011b
#### Test Trials

##### Test 1
```Bash
go run cmd/gateway/main.go # Run the middleware with port 1053
dig @127.0.0.1 -p 1053 google.com # Normal Domain resolve to 1.1.1.1 (cloudflare)
dig @127.0.0.1 -p 1053 malware.com # Static Blocklist Domain (Sink-hole to 0.0.0.0)
dig @127.0.0.1 -p 1053 x89a1zq98lbz19q7m3.biz # Zero-Day DGA Domain (High Entropy - Should BLOCK) {Didn't work}
```
The DGA High-Entropy Domain didn't work and did not BLOCK the domain.
