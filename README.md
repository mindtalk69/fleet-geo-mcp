# fleet-geo — an MCP that answers "where does this model actually run?"

[![test](https://github.com/mindtalk69/fleet-geo-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/mindtalk69/fleet-geo-mcp/actions/workflows/test.yml)

A zero-dependency MCP server (stdio, Node >= 20) that resolves the physical location of
inference for each model in the Orca fleet, and refuses to guess.

Written because a prompt rots: providers change, endpoints move, new lanes appear. A tool
that re-derives the answer from live data does not.

```
fleet-geo-mcp/
  server.mjs              MCP stdio transport + 11 tools
  src/tcpip.mjs           RFC 1792-modeled dual-stack TCP/UDP connection MIB & IPv4/IPv6 primitives
  src/native.mjs          optional Rust N-API loader with automatic pure-JS fallback
  native/fleet-geo-native Encore-style Rust N-API core (kernel sockets/processes, LPM radix trie, SNI/DNS)
  scripts/build-native.mjs compiles the Rust N-API cdylib to native/*.node (zero JS runtime deps)
  src/observe.mjs         observe_endpoints: proxy, OS socket table (TCP+UDP), strace SNI/DNS
  src/doh.mjs             DNS over HTTPS (ISP-independent dual-stack A/AAAA/CNAME evidence)
  src/sources.mjs         Cymru ASN (IPv4+IPv6), RDAP, AWS/GCP IPv4+IPv6 prefix tables, PeeringDB, crt.sh, globalping, headers
  src/geo.mjs             CIDR math (IPv4+IPv6), distance, RTT floor, region anchors, hostname fingerprints
  src/classify.mjs        evidence -> four planes -> confidence + contradictions
  src/catalog.mjs         the only hand-maintained data, plus record_fact
  catalog.json            provider seeds, all marked hypothesis until cited
  fleet.json              the lane table (W1-W7, C, B, T) - adding a lane is a one-line edit
  config.json             entitled-host allowlist + limits
  test/selftest.mjs       offline strict + online tolerant checks (IPv4 + IPv6)
  test/tcpip.test.mjs     RFC 1792 dual-stack TCP/UDP MIB & address tests
  test/observe.test.mjs   observe_endpoints checks, offline on every OS
  test/native.test.mjs    Rust N-API native core parity & kernel socket tests
  test/stdio-check.mjs    protocol surface, replayed from a recorded session
  dsh-bundle/             the DSH wrapper, shipped with the server
```

## Runs on every OS (optional Rust N-API native core)

Windows, macOS and Linux, on Node.js 20 or newer, with **zero npm dependencies**. Every tool
uses only Node built-ins and public HTTPS/DNS sources, so it works out of the box with pure JS.

For low-level kernel speed without subprocesses (an Encore-style Node + Rust N-API hybrid),
build the optional Rust native core:

```bash
npm run build:native   # produces native/fleet-geo-native.<platform>-<arch>.node
```

When present, `src/native.mjs` loads the compiled `.node` addon directly inside Node.js (still
zero `node_modules`) and transparently accelerates:

- **Kernel RFC 1792 socket & process snapshots (zero subprocesses)**: Linux `/proc/net/*` + `/proc/<pid>`, Windows `GetExtendedTcpTable` / `GetExtendedUdpTable` + `CreateToolhelp32Snapshot`, macOS `libproc`.
- **Dual-stack IPv4 + IPv6 LPM radix trie**: sub-microsecond longest-prefix match for AWS/GCP prefix tables.
- **Zero-copy protocol parsers**: bounds-checked Rust TLS `ClientHello` SNI, DNS question, and address normalizers.

Set `FLEET_GEO_NATIVE=0` to force the pure-JS fallback at any time. `explain_rules` and
`inspect_connections` report the active engine (`rust-napi` vs `js-fallback`).
The only OS-specific part is `observe_endpoints`, which picks the native tool for each OS
and never needs root or admin rights:

| | Windows | macOS | Linux |
|---|---|---|---|
| all lookup tools (`locate_model`, `fleet_status`, ...) | yes | yes | yes |
| `observe_endpoints` proxy layer | yes | yes | yes |
| `observe_endpoints` / `inspect_connections` socket MIB (native Rust) | `GetExtendedTcpTable` / `GetExtendedUdpTable` + Toolhelp32 | `libproc` | `/proc/net/*` + `/proc/<pid>` |
| `observe_endpoints` / `inspect_connections` socket MIB (JS fallback) | `netstat -ano` + PowerShell process tree | `lsof` + `ps` | `ss -tnupHa` + `ps` |
| `observe_endpoints` SNI/DNS names | via the proxy | via the proxy | proxy + `strace` (if installed) |
| CLI shims (`codex.cmd` etc.) | run through the shell | direct | direct |
| process cleanup on timeout | `taskkill /T /F` | process group | process group |

Per-OS differences in how a lane is launched live in `fleet.json` as
`observe.argvByPlatform` (for example agy needs a pseudo-TTY via `script` on Linux and
macOS). Shell examples below are PowerShell; the same commands work unchanged in bash or zsh.

## The one idea

**Four planes, never merged.**

| Plane | What it is | Why it matters |
|---|---|---|
| CONTROL | the base URL the CLI actually calls | may be a router, not the model author |
| EDGE | where TLS terminates | nearest to *you*; almost never the model |
| ORIGIN | where weights execute | **this is the answer** |
| LEGAL | entity + residency commitment | what a DPO accepts; constrains origin |

Every naive geolocation answer collapses these into one and reports the Cloudflare PoP
down the street as "the datacenter".

## Tools

| Tool | Use |
|---|---|
| `locate_model` | one lane: model / lane name / base_url -> full location card |
| `fleet_status` | every lane in one sweep -> table + roll-up |
| `trace_endpoint` | one hostname -> CNAME hops, ASN, cloud region, RDAP |
| `lookup_prefix` | one IPv4 or IPv6 address -> ASN, published cloud region, PeeringDB facilities |
| `find_regional_endpoints` | crt.sh subdomains, regional ones surfaced |
| `probe_latency` | distributed probes + the RTT floor falsifier |
| `inspect_edge` | headers from an **entitled** endpoint -> edge PoP only |
| `record_fact` | cite a provider page with a quote -> tier-A anchor |
| `observe_endpoints` | run a lane's one-line probe and record the hosts and IPs it really connects to |
| `inspect_connections` | passive RFC 1792 dual-stack TCP/UDP connection & listener MIB snapshot with IP geolocation |
| `explain_rules` | precedence, planes, confidence, falsifier |

### observe_endpoints

Config files say what a CLI *should* call; this records what it *does* call. Each lane in
`fleet.json` carries an `observe.argv` (with optional `argvByPlatform` and a `git` fixture
for jev). With `run:true` the tool runs that one prompt and watches it through three layers:

| Layer | Linux | macOS | Windows | Sees |
|---|---|---|---|---|
| logging CONNECT proxy (`HTTPS_PROXY`) | yes | yes | yes | hostname, port, bytes per tunnel |
| RFC 1792 dual-stack TCP/UDP socket MIB | Rust `/proc/net` (fallback `ss -tnupHa`) | Rust `libproc` (fallback `lsof`) | Rust IP Helper API (fallback `netstat -ano`) | every IPv4/IPv6 remote TCP (all states) & UDP endpoint + listeners |
| `strace -yy`, when installed | yes | - | - | TLS SNI hostname, DNS questions, every connect |

Nothing is decrypted: the hostname comes from the CONNECT line, the cleartext SNI or the
DNS question. Every destination IP then gets `lookup_prefix`-style facts and an `EDGE` /
`ENDPOINT` label. The result is CONTROL-plane evidence, saved under `observations/`.
It ends at the TLS edge and never proves the origin. Without `run:true` it only prints
the commands, because each lane costs one model call. `relocate:true` re-classifies the
IPs of each lane's latest saved run without running any CLI (no model calls); the original
file is kept and a `-relocated.json` file is added. agent2mind reads these files to show
which hosts each agent really calls.

**Gateway follow.** Some CLIs never leave the machine themselves: `hermes` hands each
request to its own daemon on `127.0.0.1:34101`. When a CLI connects to a loopback port,
the tool finds the process listening there (never its own proxy) and records that
process's outbound connections, split into `newConnections` (opened during the run) and
`preexisting` (pooled keep-alives open before it). New connections become this lane's
evidence (`OBSERVED_VIA_GATEWAY`, via `gateway:<pid>`); pooled ones are listed and labelled
but never counted as proof. A busy gateway may also be serving other clients, so treat
its new connections as a strong hint, not exclusive attribution. Works on every OS through
the same socket table (native core, `ss`, `lsof` or `netstat`).

### inspect_connections

A passive, zero-model-call snapshot of the host's live dual-stack TCP and UDP sockets,
modelled on **RFC 1792**'s four-table MIB:

- `tcpConnTable`: active TCP 4-tuples (`synSent` through `timeWait`), with transient state tracking
- `tcpUnspecConnTable` / `tcpListeners`: wildcard (`0.0.0.0`, `::`) and bound TCP listeners kept separate from active remotes
- `udpTable` / `udpUnspecTable`: connected UDP flows (e.g., QUIC/HTTP3 on UDP/443, DNS) and wildcard UDP listeners

Accepts optional `pid` (includes descendant process tree), `process`, `protocol` (`tcp`/`udp`/`all`),
`family` (`ipv4`/`ipv6`/`all`), and `locate:true` to enrich remote IPv4/IPv6 endpoints with ASN,
published cloud region, and `EDGE`/`ENDPOINT` plane labels. Reports `runtime.engine` (`rust-napi` or `js-fallback`).

## The answer shape

```jsonc
{
  "planes": { "control": {...}, "edge": {...}, "origin": {...}, "legal": {...} },
  "location": { "country": "KR", "region": "ap-northeast-2", "facility": null,
                "precision": "region" },   // facility > metro > region > country > unknown
  "confidence": "ANCHORED",               // ANCHORED | CORROBORATED | INDICATED | OPEN
  "confidenceWhy": "1 tier-A anchor(s): cloud-published-region",
  "contradictions": [],                   // e.g. an RTT below the fiber floor
  "evidence": [ { "id": "E2", "tier": "A", "source": "aws ip-ranges.json",
                  "observed": "3.5.140.1 falls in 3.5.140.0/22, published as AWS region ap-northeast-2" } ],
  "nextProbes": ["Region is anchored. A facility needs documentary evidence: ..."]
}
```

`precision` is the honest word for "exact". A tool that returns a street address for a
Cloudflare-fronted API is lying; one that returns `region: ap-northeast-2, precision:
region, confidence: ANCHORED` is not.

## Precedence (highest first)

1. provider documentation (cited via `record_fact`) / region encoded in the hostname
2. the cloud's **own published prefix table** (AWS `ip-ranges.json`, gstatic `cloud.json`)
3. PeeringDB facility for the serving ASN
4. RDAP / ASN registration
5. commercial geoIP databases
6. latency inference

Rule 2 is the sharpest trick: when an address falls inside a published AWS or GCP prefix,
the cloud itself tells you which region owns it. That beats every geoIP product, and it
costs nothing.

## The falsifier

Fiber runs at ~200,000 km/s, so a round trip costs **~1 ms per 100 km** of path. Real
paths are longer than the great circle, so measured RTT normally sits *above* the floor.
A measurement far *below* it is physically impossible — and therefore a hard test:

```jsonc
// probe_latency from Helsinki @1.4 ms, claimed origin Ashburn (7000 km)
{ "verdict": "FALSIFIED",
  "rows": [{ "impliedMaxDistanceKm": 140, "distanceToClaimedOriginKm": 7000,
             "floorMs": 70, "violation": { "floorMs": 70, "hardFloorMs": 53 } }] }
```

It can only ever *disprove* a claim. That is exactly what a confident answer needs.

## Guardrails in code, not just in prose

- **Entitlement gate.** `inspect_edge` refuses any host absent from `config.json`
  `entitledHosts`. Passive lookups stay open; traffic does not.
- **Pacing.** Per-source minimum intervals. These are free shared services.
- **Secret hygiene.** Auth headers are stripped before they can be echoed.
- **Provenance gate.** `record_fact` rejects a fact without an `http(s)` URL and a >=12
  char verbatim quote. An agent cannot promote its own guess to a fact.
- **No invasive technique.** DNS, RDAP, published tables, PeeringDB, crt.sh, ICMP from a
  third-party probe network. No port scanning, no whois TCP/43, no auth walls.

## Dynamic by construction

Nothing about a provider is hardcoded except what only a human can supply: who publishes
the model, and what their documentation claims.

- New endpoint? `trace_endpoint` resolves it now.
- New provider? `record_fact` with `publisher` + `match[]` adds it.
- Provider moves? Live DNS and published ranges follow; the card changes.
- Documentation ages? Every fact carries `verified_at`; `staleness()` flags anything past
  `staleAfterDays` (90) and prints "never verified" for the rest.

## Honest limits

1. For CDN-fronted APIs the origin is not externally observable — the card returns `OPEN`
   plus the exact probe that would settle it.
2. Azure publishes no queryable service-tag JSON any more, so Azure region comes from the
   resource itself (`az cognitiveservices account show ... --location`); the tool says so
   rather than guessing.
3. Passthrough aggregators (OpenRouter, Together, Fireworks) return a `provider` field per
   response. That is authoritative for the *serving entity*; the tool names it as the next
   probe instead of inventing it.
4. Dual-stack IPv4 and IPv6 addresses are both resolved through Team Cymru (`origin.asn.cymru.com` /
   `origin6.asn.cymru.com`), AWS/GCP published IPv4 + IPv6 prefix tables, and RDAP. If an address
   still yields neither ASN nor cloud-prefix data, `observe_endpoints` labels it `UNKNOWN` rather
   than presuming it is a unicast endpoint.
5. `observe_endpoints` sees where a CLI connects, which ends at the TLS edge. A CLI that
   hands traffic to a local gateway outside its process tree is followed to that gateway;
   if the gateway opens nothing new during the run, the lane stays `LOCAL_GATEWAY` with the
   gateway named, not a location.

## Develop

```powershell
cd C:\DEV\fleet-geo-mcp
npm test                          # selftest (44) + tcpip (8) + observe (12) + native (7)
npm run build:native              # optional: build Rust N-API core (native/*.node)
FLEET_GEO_NATIVE=0 npm test       # verify pure-JS fallback without native addon
node server.mjs --tool inspect_connections --args '{"locate":false}'
node server.mjs --tool lookup_prefix --args '{"ip":"2607:6bc0::10"}'
node server.mjs --tool observe_endpoints --args '{"lane":"all"}'                 # plan only
node server.mjs --tool observe_endpoints --args '{"lane":"W7","run":true}'       # one model call
node server.mjs --tool observe_endpoints --args '{"lane":"all","relocate":true}' # re-classify, no model calls
node server.mjs --list-tools
node server.mjs --tool fleet_status --args '{"limit":3}'
node server.mjs --tool locate_model --args '{"lane":"W7"}'

# full stdio session (shell redirection, not a piped child process)
cmd /c "node server.mjs < test\fixtures\stdio-requests.jsonl > test\fixtures\stdio-responses.jsonl"
node test/stdio-check.mjs
```

## Companion

[`docs/PROMPT.md`](docs/PROMPT.md) is the analyst prompt this server replaced: a static spec
that rots the moment a provider changes. Kept as the design rationale - the four planes, the
evidence ladder, the falsification pass - for when the tool's output needs arguing in prose.

## Install

Two routes - a DSH bundle or a single patch row - both in [INSTALL.md](INSTALL.md).
Placeholders there map to `$env:DSH_NODE_EXECUTABLE`, `%USERPROFILE%\.dsh\profiles\<profile>`,
and this checkout.

## License

MIT - see [LICENSE](LICENSE).