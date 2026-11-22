# Hopbits CLI

`hopbits` (`v0.2.0`) is the official command-line client for the Hopbits global measurement network. It runs on-demand network diagnostics (`http`, `tcp_connect`, `icmp_ping`, `dns`, `traceroute`, `mtr`) from residential, datacenter, and mobile vantages worldwide, inspects live network coverage and credit usage, and manages recurring checks as declarative code (`hopbits.yaml` / `hopbits.json`).

## Building from source

Requires Go 1.24 or newer:

```sh
go build -trimpath -ldflags="-s -w" -o hopbits ./cmd/hopbits
go test ./...
```

To stamp an explicit version at build time:

```sh
go build -trimpath -ldflags="-s -w -X main.version=0.2.0" -o hopbits ./cmd/hopbits
```

## Authentication

`hopbits` resolves credentials in the following priority order:

1. `--api-key <key>` global flag
2. `HOPBITS_API_KEY` (or `HOPBITS_KEY`) environment variable
3. Local credentials file (`~/.config/hopbits/credentials` on Linux/macOS, `%APPDATA%\hopbits\credentials` on Windows, mode `0600`)

Save and verify an API key interactively or via flag:

```sh
hopbits login
hopbits login --api-key hb_live_...
```

For CI/CD pipelines and non-interactive shells, export `HOPBITS_API_KEY`:

```sh
export HOPBITS_API_KEY="hb_live_..."
```

The default API endpoint is `https://api.hopbits.io` (overridable with `--api-url` or `HOPBITS_API_URL`).

## Commands

| Command | Purpose |
|---|---|
| `hopbits login` | Verify an API key against `/v1/credits` and store it in the local credentials file (`0600`) |
| `hopbits whoami` | Inspect account credit usage and balance, active/paused checks count, and live network coverage by country (`GET /v1/credits`, `/v1/checks`, `/v1/network`) |
| `hopbits probe <target>` | Run an on-demand global measurement (`http`, `tcp_connect`, `icmp_ping`, `dns`, `traceroute`, `mtr`) with latency and status assertions |
| `hopbits plan` | Preview declarative check changes and estimate daily credit spend against `hopbits.yaml` (`POST /v1/checks/plan`) |
| `hopbits apply` | Reconcile recurring checks from `hopbits.yaml` or `hopbits.json` |
| `hopbits export` | Export existing remote checks into `hopbits.yaml` (with optional `--adopt` to assign keys in place) |
| `hopbits version` | Print the CLI version and platform (`--json` supported) |

---

### `hopbits whoami` (Network, Usage & Checks Overview)

Inspects available credits (purchased, grant, reserved), recurring monitor counts, and live online node counts across countries:

```sh
hopbits whoami
hopbits whoami --json
```

---

### `hopbits probe` (On-Demand Global Measurements)

Runs an on-demand measurement across Hopbits vantages and waits for results. All six measurement kinds supported by `hopbits-agent 0.2.5` can be invoked directly from the CLI.

#### Supported measurement kinds

| `--type` value | Aliases | Description |
|---|---|---|
| `http` | (default) | HTTP/HTTPS `GET` or `HEAD` probe with status code and phase latency breakdown |
| `tcp_connect` | `tcp` | TCP three-way handshake latency to a target host and port |
| `icmp_ping` | `icmp`, `ping` | ICMP echo round-trip latency, packet loss, and reply TTL |
| `dns` | | Recursive DNS lookup over UDP or TCP against the node's ISP resolver (`isp`) or an allowlisted public resolver (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222`) across `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`, `PTR` |
| `traceroute` | `trace` | Unprivileged UDP or ICMP hop-by-hop path trace (`4..30` max hops, `1..3` probes/hop) with ASN and geolocation enrichment and automatic Hop-1/operator subnet privacy redaction |
| `mtr` | | Multi-cycle hop-by-hop packet loss and latency jitter (sample standard deviation) telemetry (`3..10` cycles, `4..30` max hops) |

#### Probe flags

| Flag | Description |
|---|---|
| `--type <kind>` | Measurement kind: `http`, `tcp` (`tcp_connect`), `icmp` (`icmp_ping`), `dns`, `traceroute`, or `mtr` (default `http`) |
| `--from <cc,...>` | Comma-separated 2-letter ISO country codes (for example `DE,US,SG`) or `ANY` |
| `--network <class>` | Network type filter: `any`, `residential`, `datacenter`, or `mobile` (default `any`) |
| `--limit <n>` | Probes per requested location (`1..10`, default `1`) |
| `--family <fam>` | Address family: `ipv4` or `ipv6` |
| `--method <m>` | HTTP method for `http` probes: `GET` or `HEAD` |
| `--path <path>` | HTTP request path override for `http` probes |
| `--port <port>` | Destination port override for `http` and `tcp_connect` probes |
| `--qtype <type>` | DNS record type for `dns` probes: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`, or `PTR` |
| `--resolver <res>` | DNS resolver for `dns` probes: `isp`, `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, or `208.67.222.222` |
| `--proto <proto>` | Transport protocol: `udp` or `tcp` for `dns`; `udp` or `icmp` for `traceroute` and `mtr` (alias `--protocol`) |
| `--max-hops <n>` | Maximum TTL hops for `traceroute` or `mtr` (`4..30`, default `24`) |
| `--probes <n>` | Probes per hop for `traceroute` (`1..3`, default `3`) |
| `--cycles <n>` | Probe cycles for `mtr` (`3..10`, default `5`) |
| `--expect-status <code>` | Fail with exit code `1` if any `http` response status differs from `<code>` |
| `--max-p95 <dur>` | Fail with exit code `1` if aggregate p95 latency exceeds `<dur>` (for example `350ms` or `1.2s`) |
| `--min-ok <n>` | Minimum successful vantage responses required (default `1`) |
| `--strict` | Fail if any requested or assigned vantage does not succeed |
| `--max-credits <n>` | Maximum credits to reserve for this measurement (`0` for default cap) |
| `--timeout <dur>` | Maximum time to wait for completion (default `35s`) |
| `--json` | Emit the complete measurement report and per-vantage payloads as JSON |

#### Examples

HTTP check with CI/CD status and p95 latency gates across residential networks:

```sh
hopbits probe https://example.com/healthz \
  --from DE,US,JP \
  --network residential \
  --expect-status 200 \
  --max-p95 400ms
```

TCP connect check to port 443:

```sh
hopbits probe example.com:443 --type tcp_connect --from DE,US
```

ICMP ping check over IPv4:

```sh
hopbits probe 1.1.1.1 --type icmp_ping --family ipv4 --from DE,SG
```

DNS lookup comparing the vantage's local ISP resolver or a public resolver:

```sh
hopbits probe example.com --type dns --qtype AAAA --resolver isp --proto udp --from DE,US
hopbits probe example.com --type dns --qtype TXT --resolver 1.1.1.1 --proto tcp --json
```

Hop-by-hop traceroute with ASN and geolocation enrichment:

```sh
hopbits probe example.com --type traceroute --proto udp --max-hops 20 --probes 3 --from DE
```

Multi-cycle MTR packet loss and jitter analysis:

```sh
hopbits probe example.com --type mtr --proto icmp --cycles 5 --max-hops 24 --from DE --json
```

---

### `hopbits plan`, `hopbits apply`, and `hopbits export` (Checks & Cost Estimation)

Recurring checks (`http`, `tcp_connect`, `icmp_ping`) can be managed declaratively in `hopbits.yaml` (or `hopbits.json`) with `${ENV_VAR}` and `${ENV_VAR:-default}` environment variable interpolation.

Example `hopbits.yaml`:

```yaml
version: 1
monitors:
  - key: edge-api-health
    name: Edge API Health
    type: http
    target: https://api.example.com/healthz
    method: GET
    interval: 1m
    locations:
      - DE
      - US
      - SG
    alert_email: true
    webhook_url: ${ALERT_WEBHOOK_URL:-}

  - key: core-dns-anycast
    name: Core Anycast Ping
    type: icmp
    target: 1.1.1.1
    family: ipv4
    interval: 5m
    locations:
      - ANY
```

Preview changes and estimate daily credit usage without modifying remote state:

```sh
hopbits plan -f hopbits.yaml
hopbits plan -f hopbits.yaml --prune --detailed-exitcode
```

`--detailed-exitcode` returns `0` when no changes are needed, `2` when changes are planned, and `1` on error.

Apply changes to Hopbits:

```sh
hopbits apply -f hopbits.yaml
hopbits apply -f hopbits.yaml --prune
```

Export existing checks from your account to `hopbits.yaml`:

```sh
hopbits export -o hopbits.yaml --adopt
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
