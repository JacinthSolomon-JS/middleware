# Middleware Gateway — Development Notes

This file summarizes implementation details for contributors. For installation, configuration, security guidance, API routes, and deployment acceptance steps, see [README.md](README.md).

## Project structure

```text
middleware/
├── configs/               Default blocklist source configuration
├── pkg/api/               REST API and WebSocket hub
├── pkg/dns/               UDP/TCP DNS resolver
├── pkg/interceptor/       NFQUEUE and packet inspection
├── pkg/modules/           Policy and list-management modules
├── pkg/pipeline/          Inspection pipeline
├── pkg/storage/           SQLite persistence
├── scripts/               Packaging and release helpers
├── web/                   Embedded management dashboard
└── main.go                Application lifecycle and firewall setup
```

The Go module is named `middleware`. Current direct dependencies include:

- `github.com/miekg/dns` for DNS wire-format parsing and UDP/TCP serving.
- `github.com/google/gopacket` for packet parsing and TLS ClientHello inspection.
- `modernc.org/sqlite` for embedded SQLite storage.
- `github.com/florianl/go-nfqueue/v2` for Linux NFQUEUE integration.
- `github.com/gorilla/websocket` for live dashboard activity.
- `github.com/gin-gonic/gin` for HTTP API routing.
- `gopkg.in/yaml.v3` for source configuration.

Use `go mod download` rather than installing dependencies individually.

## Gateway requirements

The production gateway must run on Linux with Netfilter support. It requires sufficient privileges to install firewall rules and open an NFQUEUE listener.

Enable IPv4 forwarding when routing traffic for other devices:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Persist it using the operating system's supported sysctl configuration, for example:

```bash
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-middleware-gateway.conf
sudo sysctl --system
```

Install `iptables`/`ip6tables` through the distribution package manager when needed:

```bash
# Debian or Ubuntu
sudo apt update
sudo apt install -y iptables

# Fedora or RHEL
sudo dnf install -y iptables

# Arch Linux
sudo pacman -S iptables
```

The rules use NFQUEUE, conntrack, connbytes, owner matching, comments, and NAT redirect support. The corresponding kernel modules must be available on the deployment host.

## Runtime traffic flow

```text
LAN client or local process
          |
          +---- DNS request ----> firewall DNS redirect ----> local DNS service
          |
          +---- network packet -> tagged NFQUEUE rule ------> Go interceptor
                                                               |
                                                               v
                                                        policy pipeline
                                                               |
                                                    accept, monitor, or drop
```

The interceptor parses IP and transport metadata and can inspect TLS ClientHello SNI. It does not decrypt TLS application traffic.

The DNS service applies the allowlist, configured source lists, runtime denylist, and entropy policy before forwarding permitted requests to the selected upstream resolver.

## Storage flow

```text
DNS or packet decision
        |
        v
bounded event channel
        |
        v
batch storage worker
        |
        v
SQLite activity and summary tables
```

Traffic events are buffered and written in batches. Database retention can be limited by age with `LOG_RETENTION` and by row count with `GATEWAY_LOG_MAX_ROWS`.

## Management plane

The dashboard is static HTML, CSS, and JavaScript embedded in the Go binary. It communicates with authenticated `/api/v1` REST endpoints and uses an authenticated WebSocket for live activity.

The API token is never embedded in generated dashboard HTML. The operator enters it at runtime, and the browser keeps it only in the current tab's session storage.

The management HTTP server has explicit read-header, request-read, response-write, and idle timeouts. Background API or DNS failures are returned to the main lifecycle so normal shutdown and firewall cleanup can complete.

## Source management

Default sources are defined in `configs/blocklists.yaml` and grouped by category. The manager supports:

- Enabling and disabling individual sources or categories.
- Refreshing enabled HTTPS sources.
- Adding validated custom HTTPS sources.
- Importing local host-format files.
- Persisting runtime source state in SQLite.
- Writing downloaded source caches atomically.

Downloaded feeds are bounded and parsed as host/domain rules. Failed refreshes retain the previous usable list.

## Development commands

Run the complete verification set before committing:

```bash
go test -p 1 ./...
go vet ./...
go build ./...
```

Build and run with appropriate privileges on Linux:

```bash
go build -o middleware-gateway .
sudo ./middleware-gateway
```

Remove application-tagged firewall rules without starting the gateway:

```bash
sudo ./middleware-gateway --cleanup
```

## DNS checks

With the default DNS listener:

```bash
dig @127.0.0.1 -p 1053 example.com
dig @127.0.0.1 -p 1053 malware.com
```

The first query should resolve normally when upstream connectivity is available. A configured blocked domain should receive the gateway's blocked response and appear in activity logs. Entropy-based decisions depend on the persisted threshold and whether the entropy module is in log-only or enforcing mode.

## Current verification status

- Unit tests, static analysis, and builds pass on the development toolchain.
- Dashboard integration checks cover API rendering, navigation, filters, policy lists, settings, and mobile layout.
- Native Linux checks confirmed process startup, API authentication, DNS resolution, configuration changes, graceful shutdown, and firewall cleanup.
- Inline NFQUEUE acceptance still requires a Linux host or VM whose kernel provides all firewall match modules used by the configured rules.

## Future considerations

- Evaluate nftables-native rule management or eBPF/XDP only as a separately designed migration; the current implementation installs `iptables`/`ip6tables` rules.
- Benchmark source refresh, SQLite retention, and packet handling under representative gateway traffic.
- Run the Go race detector on Linux with CGO enabled.
