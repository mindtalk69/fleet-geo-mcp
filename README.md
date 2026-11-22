# fleet-geo — an MCP that answers "where does this model actually run?"

A zero-dependency MCP server (stdio, Node >= 20) that resolves the physical location of
inference for each model in the Orca fleet, and refuses to guess.

Written because a prompt rots: providers change, endpoints move, new lanes appear. A tool
that re-derives the answer from live data does not.

```
fleet-geo-mcp/
  server.mjs              MCP stdio transport + 9 tools
  src/doh.mjs             DNS over HTTPS (ISP-independent evidence)
  src/sources.mjs         Cymru ASN, RDAP, AWS/GCP prefix tables, PeeringDB, crt.sh, globalping, headers
  src/geo.mjs             CIDR math, distance, RTT floor, region anchors, hostname fingerprints
  src/classify.mjs        evidence -> four planes -> confidence + contradictions
  src/catalog.mjs         the only hand-maintained data, plus record_fact
  catalog.json            provider seeds, all marked hypothesis until cited
  fleet.json              the lane table (W1-W7, C, B, T) - adding a lane is a one-line edit
  config.json             entitled-host allowlist + limits
  test/selftest.mjs       41 checks (offline strict, online tolerant)
  test/stdio-check.mjs    protocol surface, replayed from a recorded session
  dsh-bundle/             the DSH wrapper, shipped with the server
```

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
| `lookup_prefix` | one IP -> ASN, published cloud region, PeeringDB facilities |
| `find_regional_endpoints` | crt.sh subdomains, regional ones surfaced |
| `probe_latency` | distributed probes + the RTT floor falsifier |
| `inspect_edge` | headers from an **entitled** endpoint -> edge PoP only |
| `record_fact` | cite a provider page with a quote -> tier-A anchor |
| `explain_rules` | precedence, planes, confidence, falsifier |

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
4. IPv6 addresses skip the ASN lookup in v1 (IPv4 only).

## Develop

```powershell
cd C:\DEV\fleet-geo-mcp
node server.mjs --selftest        # 41 checks; offline strict, network tolerant
node server.mjs --list-tools
node server.mjs --tool fleet_status --args '{"limit":3}'
node server.mjs --tool locate_model --args '{"lane":"W7"}'

# full stdio session (shell redirection, not a piped child process)
cmd /c "node server.mjs < test\fixtures\stdio-requests.jsonl > test\fixtures\stdio-responses.jsonl"
node test/stdio-check.mjs
```
