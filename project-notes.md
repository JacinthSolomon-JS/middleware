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
