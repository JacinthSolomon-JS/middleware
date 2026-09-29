# Middleware Gateway

Middleware is a local-first Linux network security gateway written in Go. It combines DNS filtering, TLS SNI inspection, IP/CIDR blocking, configurable threat feeds, durable SQLite activity storage, and a responsive management dashboard in one deployable binary.

The browser interface is embedded into the Go executable, so the API and frontend are versioned and deployed together without a separate Node.js runtime.

## What is implemented

### Gateway and policy engine

- UDP and TCP DNS service with configurable upstream resolver presets.
- Domain decisions from denylist, allowlist, categorized source feeds, and entropy-based DGA detection.
- Linux NFQUEUE packet inspection with TLS ClientHello/SNI parsing.
- IPv4 address and CIDR blocking.
- Enforce and monitor operating modes.
- SQLite-backed activity records, policy state, and retention controls.
- Background source refresh and telemetry refresh operations.
- Graceful shutdown and removal of installed firewall rules.

### Management dashboard

- Responsive desktop and mobile navigation.
- Overview metrics, status indicators, traffic chart, recent activity, and live WebSocket updates.
- Analytics with time-range controls and outcome/source breakdowns.
- Searchable, filterable, paginated activity log with a detail view and clear-log action.
- Security controls for category and source management, including custom HTTPS sources.
- Denylist, IP/CIDR blocklist, and allowlist management.
- Enforce/monitor mode selection and resolver configuration.
- Loading, empty, error, authentication, and offline states.
- Keyboard-friendly controls, semantic labels, focus states, and reduced-motion support.

## Architecture

```text
Browser dashboard
    |  REST + authenticated WebSocket
    v
Go HTTP API ----> SQLite storage
    |
    +----> policy modules <---- blocklist sources
              ^
              |
DNS listener / NFQUEUE interceptor
              |
              v
       accept, monitor, or drop
```

The gateway inspects DNS requests and the SNI metadata exposed in a TLS ClientHello. It does not decrypt TLS application data and is not a man-in-the-middle proxy.

## Repository layout

```text
main.go                 Application lifecycle, listeners, firewall setup
configs/                Default blocklist source configuration
pkg/api/                REST API, WebSocket hub, and access controls
pkg/dns/                DNS server and upstream resolution
pkg/interceptor/        Packet parsing and NFQUEUE integration
pkg/modules/            Domain, IP, entropy, and source policy modules
pkg/pipeline/           Inspection pipeline and verdict handling
pkg/storage/            SQLite persistence and activity queries
web/                    Embedded dashboard and frontend tests
scripts/                Build and packaging helpers
```

## Requirements

- Linux on the deployment host.
- Go 1.27.1 or a compatible newer toolchain.
- Root privileges or the capabilities required to manage NFQUEUE/firewall rules.
- `iptables`/`ip6tables` and kernel support for NFQUEUE, conntrack, connbytes, and NAT redirect rules.

The source code and ordinary unit tests can be built on other operating systems. Inline packet interception must be exercised on Linux.

## Build and run

```bash
go mod download
go test -p 1 ./...
go build -o middleware-gateway .
sudo ./middleware-gateway
```

The default dashboard/API address is `http://127.0.0.1:8080`, and the DNS listener defaults to `127.0.0.1:1053` over UDP and TCP.

On first launch, the gateway creates a 32-byte random management token in `gateway_token` unless a token or alternate token file is configured. Use that value when the dashboard requests authentication. Keep the token file private.

## Configuration

Configuration is available through environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GATEWAY_API_ADDR` | `127.0.0.1:8080` | Dashboard and management API listen address |
| `GATEWAY_DNS_ADDR` | `127.0.0.1:1053` | UDP/TCP DNS listen address |
| `GATEWAY_DB_PATH` | `gateway.db` | SQLite database path |
| `GATEWAY_API_TOKEN` | generated | Explicit bearer token |
| `GATEWAY_API_TOKEN_FILE` | `gateway_token` | Token file path |
| `GATEWAY_NFQUEUE_NUM` | `0` | NFQUEUE number |
| `GATEWAY_INTERCEPT_PROTO` | `all` | Intercept `all`, `tcp`, or `icmp` traffic |
| `GATEWAY_INTERCEPT_PORT` | `443` | TCP destination port in TCP-only mode |
| `GATEWAY_INTERCEPT_MAX_PACKETS` | `8` | Initial packets inspected per connection |
| `GATEWAY_DNS_REDIRECT` | enabled | Set to `0` to disable local DNS redirection |
| `GATEWAY_IPV6` | disabled | Set to `1` to install IPv6 rules |
| `GATEWAY_OWNER_UID` | process UID | UID excluded from interception to avoid loops |
| `GATEWAY_LOG_SAMPLE_ALLOW` | `0` | Sampling interval for allowed events; `0` records all |
| `GATEWAY_LOG_MAX_ROWS` | unlimited | Positive maximum retained activity rows |
| `LOG_RETENTION` | unlimited | Positive Go duration, such as `168h` |

Example:

```bash
sudo env \
  GATEWAY_API_ADDR=0.0.0.0:8080 \
  GATEWAY_DNS_ADDR=0.0.0.0:1053 \
  LOG_RETENTION=168h \
  GATEWAY_LOG_MAX_ROWS=250000 \
  ./middleware-gateway
```

If the management API is exposed beyond loopback, place it behind a trusted TLS reverse proxy and restrict network access. The API still requires its bearer token.

## Management API

All management endpoints are under `/api/v1`. Authenticated operations include:

- `GET /summary` and `GET /summary/:id`
- `GET|POST|DELETE /blocklist`
- `GET|POST|DELETE /allowlist`
- `GET|POST /mode`
- `GET|POST|DELETE /ipblocklist`
- `GET|DELETE /logs`
- `GET /activity/recent`
- `GET|POST /resolver`
- `GET /sources` and `GET /categories`
- source/category toggle, refresh, custom URL, and upload operations

`GET /api/v1/ws` supplies live activity. WebSocket authentication uses the supported subprotocol flow, and the server validates the request origin.

## Security controls

- Constant-time bearer-token comparison.
- Loopback Host allowlist on the management surface.
- Same-origin validation for WebSocket upgrades.
- Owner-UID exclusions to prevent the gateway from intercepting its own traffic.
- HTTPS enforcement for custom remote source URLs.
- Parameterized SQLite operations and bounded API query inputs.
- Firewall rules tagged for deterministic cleanup during shutdown.

## Verification performed

The completed implementation was checked at several layers.

### Automated Go checks

```bash
go test -p 1 ./...
go vet ./...
go build ./...
```

These checks pass. The automated tests cover API bearer authentication, Host validation, resolver presets, embedded frontend delivery, token handling, dashboard views/routes, and responsive metadata.

The race-enabled suite also passes on Alpine Linux 3.24.2 with CGO and the standard C build toolchain:

```bash
./scripts/test-race.sh
```

### Frontend integration checks

The dashboard was run against the API and exercised in a browser for:

- API data loading and overview rendering.
- Navigation across every dashboard view.
- Search, filters, pagination, and activity details.
- Domain, IP/CIDR, and allowlist changes.
- Mode and resolver changes.
- Loading, empty, error, and authentication behavior.
- Desktop and mobile layouts, including horizontal-overflow checks.
- JavaScript syntax validation.

### Linux runtime checks

A native Linux build was tested in Alpine Linux 3.24.2. The Go tests, CGO race detector, vet checks, and binary build passed. Runtime verification confirmed application startup, NFQUEUE connection, dashboard/API authentication, DNS resolution, mode and resolver mutations, graceful shutdown, and firewall cleanup.

The WSL test kernel rejected the project's `connbytes` iptables match with exit status 4. That is an environment/kernel capability limitation, not a frontend failure. A final deployment acceptance test should therefore validate inline packet verdicts on the intended physical Linux gateway or VM with the required Netfilter modules enabled.

## Deployment acceptance checklist

Before placing the gateway on a production network:

1. Confirm NFQUEUE, conntrack, connbytes, NAT, and IPv6 modules required by the chosen configuration.
2. Back up the host firewall configuration and verify rule coexistence.
3. Set a protected API token and restrict access to the management listener.
4. Confirm DNS resolution, blocked-domain sinkholing, SNI verdicts, and IP/CIDR decisions from a test client.
5. Exercise shutdown/restart and verify that tagged firewall rules are removed and restored correctly.
6. Set database retention limits appropriate for available disk space.

## Current status

The frontend software is complete for the implemented backend surface: its pages, interactions, API integration, responsive states, authentication flow, and live-update channel are in place and tested. The remaining work is deployment-specific validation on the target Linux gateway, especially kernel/firewall compatibility and real routed client traffic.
