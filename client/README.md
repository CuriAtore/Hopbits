# Hopbits node client

Hopbits is a measurement network. People run a small node on their own
internet connection, and the node runs short, bounded network measurements
that Hopbits customers ask for from the node's location: is this website up,
how long does a TCP connect take, what is the round-trip time to this
address. This repository is the open-source node: the wire protocol, the
measurement modules, the safety layer that bounds everything a node can be
made to send, and the `hopbits-agent` program.

## What a node does

- It keeps **one outbound WebSocket over TLS 1.3** to the Hopbits gateway
  (`wss://gw.hopbits.io/v1/node`). It never listens on a port.
- It identifies itself with an Ed25519 **device key** it creates on first run.
  The node id is derived from that key; delete the key and the node becomes a
  new node.
- It receives **signed jobs**. A job counts only with a valid signature from a
  dispatcher key certified by the root keys compiled into the binary, and only
  if it names this node. Everything else is refused before it is parsed.
- Each job passes the module's own checks and then the **safety layer**
  before the module may touch the network. The safety layer chooses the
  address, owns every socket and charges the compiled caps.
- The node signs each **result**, stores it on disk and resends it until the
  gateway acknowledges it.
- It keeps a local log of its **last 100 jobs** (`jobs.log` in the data
  directory) naming each job's kind, target host, outcome and error.

### The measurements

| Kind | What it measures | Limits compiled into the module |
|---|---|---|
| `http` | One GET or HEAD request: status, timing phases, a hash and size of up to 10,000 body bytes, selected response headers | GET or HEAD only; timeout 2-30 s; the body is read to 10,000 bytes, hashed and discarded; redirects are reported, never followed; at most 8 response headers from a fixed allowlist |
| `tcp_connect` | How long a TCP connect takes | 1 to 3 connections, 1 s apart, each closed at once without sending data; timeout 1-10 s |
| `icmp_ping` | ICMP echo round trips and the reply TTL | 3 to 16 packets, at least 200 ms apart; timeout 0.5-5 s per packet |
| `dns` | One recursive DNS lookup over UDP (with automatic RFC 1035 TCP retry on `TC=1`) or TCP against `isp` or an allowlisted public resolver | Resolvers limited to `isp`, `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, or `208.67.222.222`; record types `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`, `PTR`; timeout 0.5-10 s; at most 32 answer records; local `/etc/resolv.conf` IP never leaves the node when `isp` is used |
| `traceroute` | Unprivileged UDP or ICMP hop-by-hop path discovery | 4 to 30 max hops (1-30 TTLs), 1 to 3 probes per hop; timeout 0.3-2 s per probe; shared 50 pps token bucket; mandatory Hop-1, RFC 1918, CGNAT, and operator `/24` & `/48` subnet redaction inside the client |
| `mtr` | Unprivileged multi-cycle hop-by-hop packet loss and latency jitter (sample standard deviation) telemetry | 3 to 10 cycles across 4 to 30 max hops, at least 80 ms between cycles; timeout 0.3-1.5 s per probe; 320-packet per-lease cap under the shared 50 pps token bucket; mandatory Hop-1 and operator subnet redaction inside the client |

ICMP (`icmp_ping`) works on Linux and macOS, through unprivileged ping sockets
where the system allows them and raw sockets otherwise, and hop-limited
probing (`traceroute` and `mtr`) runs unprivileged on Linux via kernel
`IP_RECVERR` / `IPV6_RECVERR` error queues. Where the host OS does not support a
transport (for example on Windows), the node simply does not advertise that
capability.

## Safety promises

These limits are constants in this source code. The server can lower some of
them for a session, but no message from the server can raise them.

**No private targets and not the operator's own network.** A job may never
connect to private, loopback, link-local, cloud-metadata, shared (CGNAT),
multicast, documentation, benchmarking or reserved addresses; IPv6 targets
must be global unicast, and IPv4-mapped and NAT64 addresses are judged by the
IPv4 address they carry. The node also refuses its own network: the prefixes
of its interfaces, the public address the gateway sees (and its /24, or /48
for IPv6) and the /48 of each of its global IPv6 addresses. These checks run
when a job is admitted and again right before every connection. Targets the
server resolved come with the address pinned in the signed job; the node
connects to that address and nothing else.

**Compiled caps.** At most 300 jobs a minute and 16 at a time; at least 55 s
between two jobs to the same domain or the same /24 (/48 for IPv6); at most 6
jobs in any 59 minutes to one domain; at most 50 ICMP/trace packets a second,
16 packets per ping, and 320 hop-limited probes per trace/MTR lease; and a
daily traffic budget of 200 MB, which `HOPBITS_DAILY_MB` can lower. (Until
2026-11-15 the jobs a minute, the jobs at a time and the ICMP packets a second
were 30, 4 and 10; the owner raised them as too low a ceiling for customers
with thousands of checks. The spacing, the 59-minute cap and the traffic budget
did not change. `TestAgentCapsCompiled` in `safety/guard_test.go` pins all of
them.)

**No other ports.** `http` uses ports 80, 443, 8080 and 8443 and
`tcp_connect` ports 443 and 80. `dns` uses port 53 solely against the
allowlisted public resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`,
`208.67.222.222`) or the host's configured `/etc/resolv.conf` nameserver, and
`traceroute` / `mtr` send unprivileged UDP probes to ports `33434..33493` (or
ICMP echo probes) with zero payload read back beyond kernel `IP_RECVERR` /
`ICMP` time-exceeded headers. Remote-access, mail, file-sharing, database
and cache ports (21, 22, 23, 25, 110, 135, 137-139, 143, 445, 465, 587, 993,
995, 1433, 3306, 3389, 5432, 5900, 6379, 11211 and 27017) are never used. Any
other port, and the lifting of the per-domain limit, needs a target grant: a
statement, signed by a separate key the compiled roots certify, that the
owner of the target proved control of it.

**GET and HEAD only.** No request bodies, cookies, credentials or custom
headers. On a target without a grant the path is at most 128 bytes and has no
query string or fragment. Response bodies never leave the node: only their
size, their hash and a few allowlisted headers.

**Attribution.** Every HTTP request carries the User-Agent
`HopbitsProbe/1 (+https://hopbits.io/probe)` and an `X-Hopbits-Probe` header
with the measurement id, and every ICMP echo carries
`https://hopbits.io/probe` in its payload, so anyone who sees the traffic can
find out what it is and how to opt out.

**Only measurements.** The node runs the measurement kinds compiled into it
and nothing else; you can switch any of them off with
`HOPBITS_DISABLE_KINDS`.

## Configuration

Every setting comes from an environment variable, and the flag of the same
meaning overrides it (`hopbits-agent -h` lists them).

| Variable | Flag | Meaning | Default |
|---|---|---|---|
| `HOPBITS_GATEWAY` | `-gateway` | Gateway node endpoint. `wss://` only; `ws://` is accepted only to a loopback address, for development | `wss://gw.hopbits.io/v1/node` |
| `HOPBITS_DATA_DIR` | `-data-dir` | Device key, buffered results, state and job log | `/var/lib/hopbits` on Linux; a `hopbits` folder in the user config directory elsewhere |
| `HOPBITS_ENROLL` | `-enroll` | Optional fleet enrolment token. Prefer the variable (for example in an `--env-file` of mode 0600): command lines are visible to other users | none |
| `HOPBITS_DISABLE_KINDS` | `-disable-kinds` | Comma-separated kinds this node never runs, such as `icmp_ping` | none |
| `HOPBITS_NETWORK_MODE` | `-network-mode` | How the node reaches the network: `host`, `bridge`, `rootless`, `podman` or `native` | `native`, or unspecified inside a container |
| `HOPBITS_DAILY_MB` | `-daily-mb` | Daily traffic budget in MB; it can only lower the compiled 200 MB (in `anchor` mode, unset means unlimited) | `200` (`0` in anchor mode) |
| `HOPBITS_LOG_LEVEL` | `-log-level` | `debug`, `info`, `warn` or `error` | `info` |
| `HOPBITS_AUTO_UPDATE` | `-auto-update` | Verify and stage signed updates from the root-certified release manifest (`true`/`false`) | `true` |
| `HOPBITS_MODE` | `-mode` | Operating mode: `node` or `anchor` | `node` |
| `HOPBITS_ANCHOR_LISTEN` | `-anchor-listen` | Listen address for HTTP/1.1 calibration & WebSocket echo in `anchor` mode | `:8443` |
| `HOPBITS_ANCHOR_DOMAIN` | `-anchor-domain` | Anchor domain allowed on Host header in `anchor` mode | none |
| `HOPBITS_ANCHOR_CERT` | `-anchor-cert` | Wildcard TLS certificate PEM path (required on non-loopback `anchor` listeners) | none |
| `HOPBITS_ANCHOR_KEY` | `-anchor-key` | TLS private key PEM path paired with `HOPBITS_ANCHOR_CERT` | none |
| `HOPBITS_ANCHOR_ICMP` | `-anchor-icmp` | Attach an ICMP echo observer in `anchor` mode when OS permissions allow | `true` |

The data directory holds:

- `node.key`: the device key (mode 0600). Keep it private; deleting it makes
  this a new node.
- `state.json`: reconnect windows and verified key revocations.
- `traffic.json`: persisted UTC day traffic counter for `HOPBITS_DAILY_MB`.
- `pending/`: signed results not yet acknowledged (at most 500, kept 24 h).
- `jobs.log`: the last 100 jobs.
- `bin/hopbits-agent`: staged signed release binary written by self-update.

Stop the agent with Ctrl+C or SIGTERM: it stops taking jobs, cancels the
ones still running, waits for them to end and exits. A second signal exits at
once. Results not yet acknowledged stay in `pending/` and are sent on the
next start.

## The module system

A module is one kind of measurement. The contract is in [`module/`](module/):

```go
type Module interface {
	Kind() string                // registry name, such as "icmp_ping"
	Version() uint32             // kind version
	Class() nodev1.JobClass      // JOB_CLASS_MEASURE
	Needs() Needs                // TCP or ICMP, and the ports used without a grant
	SelfTest(ctx context.Context, env Env) []protocol.Capability
	Check(job *Job) error        // validate params against compiled limits, no I/O
	Run(ctx context.Context, job *Job, tn TargetNet) Result
}
```

Modules never open sockets themselves. `Run` gets a `TargetNet` from the
safety layer, bound to the job's validated target: `DialTCP` connects only to
that address and port, `Pinger` sends echoes only to that address under the
ICMP rate cap, `CheckHTTP` applies the request rules and `ProbeHeaders`
returns the attribution headers. A static test in
[`modules/all`](modules/all/guard_test.go) parses every module and fails if
one imports a networking package or calls a dialer directly.

To add a module:

1. Add its params and result messages under
   [`proto/hopbits/measure/v1`](proto/hopbits/measure/v1) and regenerate the
   code (`go generate github.com/hopbits/client`).
2. Write a package under [`modules/`](modules/) that implements
   `module.Module`. Put every limit in `Check` as a compiled constant, and
   check again in `Run`.
3. Add one line to [`modules/all/all.go`](modules/all/all.go).
4. Hopbits adds the matching kind on the server; nodes advertise the new kind
   in their capabilities, so old and new clients run side by side.

## Building and running

```sh
go build ./...
go test ./...
```

A release build compiles in the production root keys (the `RELEASE_ROOTS` value in
[`Dockerfile`](Dockerfile)) and sets its version:

```sh
go build -trimpath -ldflags "-s -w -X main.version=0.2.5 -X main.releaseRootsCSV=$HOPBITS_RELEASE_ROOTS" -o hopbits-agent ./cmd/hopbits-agent
```

A build without production root keys refuses to start, and a node that took such a release from
the update address cannot be brought back from the server. Official releases are built from
clean source, signed offline with the root-certified Ed25519 release key via `cmd/hopbits-release`,
and published through the signed update manifest verified against the compiled `RELEASE_ROOTS`.

### Docker (Linux)

Build the minimal static image from the `client/` root:

```sh
docker build -t hopbits-agent:0.2.5 --build-arg VERSION=0.2.5 .
```

Prepare an environment file readable only by the owner (if enrolling a fleet node or setting options):

```sh
cat <<'EOF' > hopbits.env
HOPBITS_NETWORK_MODE=host
# HOPBITS_ENROLL=<enrolment-token>
EOF
chmod 600 hopbits.env
```

Run the node container with all Linux capabilities dropped and persistent state in `/var/lib/hopbits`:

```sh
docker run -d --name hopbits \
  --cap-drop ALL \
  --network host \
  --restart always \
  --env-file hopbits.env \
  -v hopbits:/var/lib/hopbits \
  hopbits-agent:0.2.5
```

Notes for containerized Linux runs:

- **Capabilities & ICMP**: `--cap-drop ALL` runs unprivileged (`uid=65532`). Unprivileged ICMP ping sockets work when the host kernel permits the container group in `/proc/sys/net/ipv4/ping_group_range` (or set `--sysctl net.ipv4.ping_group_range="0 2147483647"` if needed); otherwise `icmp_ping` self-test disables ICMP automatically and the node still serves HTTP and TCP checks.
- **Bridge / Podman modes**: when not using `--network host`, set `HOPBITS_NETWORK_MODE=bridge` (or `rootless` / `podman`) in `hopbits.env`. In non-host modes, IPv6 targets are refused automatically unless the gateway observes the container's public IPv6 address.
- **Anchor mode**: pass `HOPBITS_MODE=anchor` with mounted wildcard TLS certificate files (`-v /etc/hopbits/tls:/tls:ro`), setting `HOPBITS_ANCHOR_CERT`, `HOPBITS_ANCHOR_KEY`, `HOPBITS_ANCHOR_DOMAIN`, and exposing `HOPBITS_ANCHOR_LISTEN` (`:8443` or `-p 443:8443`). Add `--cap-add NET_RAW` when running an anchor container that should capture inbound ICMP echo nonces and arriving TTLs (otherwise the raw ICMP observer logs a warning and falls back to kernel echo replies).
- **Self-update opt-out**: signed updates from `pause.anchor.hopbits.io` stage into `/var/lib/hopbits/bin/hopbits-agent` and re-exec by default; set `HOPBITS_AUTO_UPDATE=false` to disable automatic self-updates while keeping manifest verification active.

### Development

A development build trusts one root key from `HOPBITS_DEV_ROOT` instead of
the compiled roots, so it talks only to a development gateway whose
dispatcher key that root certified:

```sh
export HOPBITS_DEV_ROOT=<base64 root public key of your development gateway>
export HOPBITS_GATEWAY=ws://127.0.0.1:8443/v1/node
export HOPBITS_DATA_DIR=./devdata
go run -tags devroots ./cmd/hopbits-agent
```

On Windows PowerShell, set the variables with `$env:HOPBITS_DEV_ROOT = "..."`
and so on. The node logs its id, then `connected to the gateway` once the
gateway's signed Welcome checks out.

The `hopbits_unsafe_testing` build tag exists only for end-to-end tests: it
lets the safety layer and the modules reach a test server on a loopback
address and a high port. Release builds never set it, and without it the
safety layer refuses those test settings at start.
