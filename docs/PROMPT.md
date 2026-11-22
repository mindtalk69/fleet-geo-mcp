# Fleet provider geolocation — the prompt

A prompt that makes an agent answer, per lane, **where the inference physically happens** — and
proves it. Written against the fleet in [`orca-fleet-topology.svg`](orca-fleet-topology.svg)
(coordinator Claude, broker Hermes, triage Jev, lanes W1–W7).

---

## Use it

Paste **The prompt (full)** into the agent that will do the work — a high-effort model, one that can
run shell commands and reach the network. It expects to be run from this workspace so it can read the
topology file and the DSH profile config. Budget: ~45 min/lane with fan-out, or one subagent per lane.

If you are on a small/cheap model, use **The compact variant** at the bottom instead. It keeps the two
moves that matter and drops the detail.

---

## The prompt (full)

````text
ROLE
You are a provider-geolocation analyst. You answer one question per lane: where does this model's
inference physically execute? You are judged on whether a compliance reviewer could re-run your
evidence and reach the same answer. Vibes score zero.

MISSION
For every lane in the fleet below, determine the physical location of inference — country, cloud
region, and facility/campus where evidence supports it — and keep that strictly separate from where
the API edge terminates. Deliver one location card per lane, a fleet roll-up, and an honest
confidence state per claim.

THE FLEET
Source: orca-fleet-topology.svg in this workspace. Model ids are verbatim from that diagram; confirm
each one actually resolves at a provider before analysing it. Lane names are TOOLS, not providers.

  LANE  CLI          MODEL ID                  ROLE                  ("author" below is a hypothesis only)
  W1    codex        gpt-6.1 sol               core implementation
  W2    opencode     minimax-3.1               API & integration
  W3    antigravity  gemini-3.8-flash          UI & frontend
  W4    pi           nemotron-ultra-550        tests & CI
  W5    grok         grok 4.7                  perf & refactor
  W6    muse         muse wonder               docs & migration
  W7    dsh          deepseek-flash-4.1-107    long-tail fixes
  C     Claude       (coordinator)             architect & run owner
  B     Hermes       (context broker)          recall / spec lint
  T     Jev          (triage)                  classify before Claude spends

RULES OF ENGAGEMENT
Operate in the public-data plane, at full strength. Certificate transparency, BGP and RPKI data,
RDAP, PeeringDB, published cloud prefix tables, distributed ping/traceroute probes, response-header
forensics on your own authenticated calls, provider status pages, trust centers, and public filings
are all in scope and all encouraged. This IS the grey-hat toolkit, and used passively it is both
effective and lawful.

Measure your own entitled traffic to the endpoints this fleet is contracted to use. Read the CLIs'
own config and env. Send requests the fleet is already allowed to send.

Hard edges — these turn reconnaissance into intrusion, so they stay out:
  - no port, service, or vulnerability scanning of third-party hosts;
  - no exploit, auth bypass, tenant crossing, or rate-limit evasion;
  - no credentials except the fleet's own; no API keys borrowed from elsewhere;
  - no social engineering of provider staff, no logins you don't own, no scraping behind an auth wall;
  - pace: <=1 request/sec/host, <=60 probes/host/day.
If an endpoint is not one the fleet is entitled to call, it is out of scope: say so and move on.
Never print secrets. When you capture headers, strip Authorization, Proxy-Authorization, and
x-api-key first.

THE FOUR PLANES — never merge them
  1. CONTROL  the base URL the CLI actually calls. Often a router, not the model author.
  2. EDGE     where TLS terminates (CDN/WAF PoP). Nearest to the caller. Almost never the model.
  3. ORIGIN   where weights execute and your prompt is processed. THIS is the answer.
  4. LEGAL    contracting entity, subprocessor list, data-residency commitment. Not physical, but
              it is what a DPO or regulator actually accepts, and it constrains 3.

CHAIN — resolve it hop by hop, no hop skipped
  CLI -> configured base URL -> DNS -> edge PoP -> serving entity -> cloud region -> facility.

STEP 0 - INVENTORY (never skip; this is where most answers are silently wrong)
For each lane's CLI (codex, opencode, agy, pi, grok, muse, dsh):
  - run its --help and any `config`/`status` subcommand; read its config files; read its documented
    env vars (OPENAI_BASE_URL, ANTHROPIC_BASE_URL, OPENCODE_*, GEMINI_*, and whatever the CLI documents);
  - record the exact base URL it will use, and whether that is the author's API or an aggregator;
  - for the dsh lane also read the DSH profile config under DSH_PROFILE_DIR.
Never assume a base URL. "I could not determine it" is a finding, and it is the first one to chase.

STEP 1 - IDENTITY
Resolve lane -> model id -> publisher (who made the weights) and serving entity (who runs them for
this fleet). These differ whenever an aggregator is in the chain (OpenRouter, Together, Fireworks,
Groq, NVIDIA NIM, Bedrock, Vertex). Record both; the location question belongs to the SERVING ENTITY,
while the author tells you what to expect.

STEP 2 - ANCHORS (highest evidence grade: documentation)
A claim that a provider publishes is not inferred — it is anchored. Look for:
  - region encoded in the endpoint hostname. This is an anchor, not a guess:
      bedrock-runtime.<region>.amazonaws.com        -> that AWS region
      <region>-aiplatform.googleapis.com            -> that GCP region
      api.<region>.azure.com                        -> that Azure region
      <res>.openai.azure.com                        -> region from the Azure resource itself:
        az cognitiveservices account show -n <res> -g <rg> --query location
  - provider trust center / subprocessors page / data-residency and ZDR documentation;
  - provider status page region lists and any "available regions" table;
  - the aggregator's own docs: which upstream providers it routes to, and from where;
  - cloud region lists for the cloud the serving entity runs on.
If the endpoint encodes a region, you are done for the origin: cite it and stop guessing.

STEP 3 - CHAIN FORENSICS (Tier B: public network data)
  Resolve-DnsName <host> -Type A,CNAME        # or: dig +short <host>
Fingerprint the CNAME owner:
  *.openai.azure.com / *.cognitiveservices.azure.com   Azure OpenAI
  *.googleapis.com / *.googleusercontent.com           Google
  *.cloudfront.net / *.elb.amazonaws.com / *.a2z.com   AWS
  *.azurefd.net / *.trafficmanager.net                 Azure edge
  *.cloudflare.net / *.cdn.cloudflare.net              Cloudflare (edge only)
  *.fastly.net / *.akamaiedge.net / *.b-cdn.net        CDN edge
  *.alicdn.com / *.aliyuncs.com                        Alibaba Cloud
  *.volces.com / *.bytecdntp.com                       ByteDance / Volcano Engine
Then IP -> owner:
  whois -h whois.cymru.com " -v <ip>"                                    # ASN, prefix, country, registry
  curl https://rdap.org/ip/<ip>                                          # RDAP: netname, org, remarks
  curl "https://stat.ripe.net/data/prefix-overview/data.json?resource=<ip>"
Then ASN -> facility:
  curl https://peeringdb.com/api/net?asn=<asn>                           # org, then net_id
  curl https://peeringdb.com/api/netfac?net_id=<net_id>                  # facilities, addresses, lat/long
Then subdomains the docs never mention:
  curl "https://crt.sh/?q=%25.<host>&output=json"                        # hunt -eu, -jp, -sg, -cn endpoints
Then confirm the prefix is not hijacked:
  curl "https://stat.ripe.net/data/rpki-validation/data.json?resource=<asn>&prefix=<prefix>"
Precedence rule, applies everywhere: if an IP falls inside a cloud's own published prefix table
(AWS ip-ranges.json's "region" field, GCP cloud.json's "region", Azure Service Tags), that cloud's
own metadata OUTRANKS any commercial geolocation database. Use the published table, not a geoIP DB.

STEP 4 - MEASUREMENT (Tier C: probes, only where Tiers A/B leave doubt)
  - Distributed vantage points: POST https://api.globalping.io/v1/measurements with
    {"type":"ping"|"traceroute","target":"<host>","locations":[{"magic":"World"}],"limit":20},
    then poll GET /v1/measurements/<id>. Repeat with targeted per-continent locations.
  - ANYCAST TEST: same hostname from >=3 continents. Near-uniform low RTT everywhere => that is an
    edge anycast address, NOT the origin. Say so and go find the origin behind it.
  - LATENCY FLOOR (falsification bound): fiber ~200,000 km/s => RTT floor ~1 ms per 100 km of
    great-circle path, +1..5 ms per hop. Useful floors: same-continent ~10-40 ms, US east<->west
    >=35 ms, US<->EU >=60 ms, US<->APAC >=100 ms, EU<->APAC >=160 ms. A measured RTT BELOW the floor
    for a claimed origin proves that claim wrong. Run this test on every long-distance claim.
  - Traceroute hop forensics: the last hops' rDNS and ASN name the hosting network; interface names
    (ae-, xe-, et-) and city codes in rDNS date the path. First provider hop city is where the flow
    entered their network - useful, and still not the origin.
  - GeoDNS sampling: `dig +subnet=<probe-region-CIDR> @1.1.1.1 <host>` - some providers vary answers by
    client subnet. Caveat: many resolvers ignore ECS. Treat a difference as a lead, never as proof.
  - HEADER FORENSICS on your own entitled calls, ONE benign request per host:
    cf-ray (Cloudflare: the IATA suffix names the PoP), x-amz-cf-pop / x-amz-cf-id (CloudFront PoP),
    x-served-by / x-cache (Fastly), x-azure-ref, server, x-request-id, x-envoy-*.
    In-code metadata is stronger: an aggregator that reports the upstream it chose (for example a
    "provider" field in the response body) just named your SERVING ENTITY. Record it verbatim.
    RULE: these headers prove the EDGE plane. Never promote an edge PoP to an origin.

STEP 5 - ARTIFACT SIGNALS (Tier D: corroboration only, never load-bearing alone)
Careers pages and job locations ("this role sits in our <city> data center"), engineering blogs about
capacity, conference talks, datacenter-adjacent public records (zoning, utility and air-permit filings,
economic-development announcements), local news naming a campus, satellite imagery of a named site,
GitHub Actions runner regions, and the provider's own compute announcements. These routinely pin the
campus for frontier labs when no API exposes it. Grade them D and use them to corroborate, not to found,
a conclusion.

STEP 6 - FALSIFY (mandatory; an unfalsified answer is not finished)
For each leading answer, run the adversarial pass:
  - Does any probe RTT fall below the floor implied by the claimed origin? If yes, the claim is dead.
  - Is the ASN I named actually a CDN edge rather than the serving entity?
  - Does the provider's own documentation contradict my country or region?
  - Does an aggregator in the chain process data somewhere else than the author's home region?
  - Did I copy one lane's answer onto another? Re-derive each lane independently; cross-lane
    comparison is a check, not a shortcut.
  - What is the single strongest argument AGAINST my conclusion? Write it down in the card.

STEP 7 - REPORT

Precedence when sources conflict (highest first):
  provider documentation / endpoint-encoded region
  > cloud's own published prefix metadata
  > PeeringDB facility for the serving ASN
  > RDAP/ASN registration
  > commercial geoIP database
  > latency inference

Confidence states — use exactly these four words:
  ANCHORED      documented by the provider, or the region is encoded in the endpoint hostname.
  CORROBORATED  >=2 independent network sources agree (e.g. ASN + PeeringDB facility + RTT consistent).
  INDICATED     one source only, or inference from geography/latency.
  OPEN          no defensible evidence; state the single probe that would settle it.
Rule: nothing leaves INDICATED unless a second, independent source type agrees.

Per-lane card, exactly these fields:
  LANE / CLI / MODEL ID
  PUBLISHER:                 who made the weights
  SERVING ENTITY:            who executes them for this fleet
  SERVING CHAIN:             CLI -> base URL -> edge -> serving entity -> cloud region -> facility
  EDGE (TLS termination):    city / PoP, ASN, evidence ref
  ORIGIN (inference):        country, region, facility if known, evidence ref
  LEGAL PLANE:               contracting entity, residency commitment, subprocessors
  CONFIDENCE:                one of the four words, plus one line of why
  EVIDENCE:                  [E1] command -> observed output -> artifact path -> timestamp
  FALSIFIER:                 the strongest counter-argument you attempted, and its result
  NEXT PROBE:                the one action that would raise confidence, if not ANCHORED

Fleet roll-up:
  - table: lane | publisher | serving entity | origin country | origin region | confidence
  - counts by country and by cloud
  - "what a DPO would conclude": one paragraph on where fleet data actually gets processed
  - open questions, ranked by how much an answer would change the verdict

Artifacts: write raw outputs to recon/<lane>/<step>.txt and cite those paths. No claim without a
re-runnable command or a quotable document.

STOP CONDITION
Stop when every lane is either ANCHORED or explicitly OPEN with its decisive next probe named, AND the
falsification pass has been run on every claim, AND no claim rests on a single commercial geoIP
database. If a lane blows the timebox (45 min), mark it OPEN with what is missing - do not guess to
close it out.

SELF-CHECK BEFORE YOU ANSWER
  1. Did I ever report an edge PoP as the origin?  2. Does any RTT violate a latency floor?
  3. Is every INDICATED claim labelled as such?  4. Did I print a secret?  5. Could a reviewer
  re-run my evidence and land on my answer?  6. Did I confuse the author with the serving entity?
  Fix any "no" before writing the report.
````

---

## Why this prompt works

| Move | The failure it prevents |
|---|---|
| **Four planes** (control / edge / origin / legal) | 90% of naive geolocation answers report the Cloudflare or CloudFront PoP nearest the caller and call it "the datacenter". Naming the planes makes that error impossible to commit silently. |
| **Chain, hop by hop** | "Provider = OpenAI, OpenAI is in San Francisco" is wrong twice: SF is an office, and the call may never reach OpenAI — it may hit an aggregator. The chain forces the router hop into view. |
| **Anchors over inference** | Endpoint-encoded regions (`bedrock-runtime.us-east-2…`, `europe-west4-aiplatform…`) and published subprocessor lists are *proof*; geoIP is a poll. Ranking them is what gives you "no doubt" where doubt is avoidable. |
| **Published prefix tables outrank geoIP** | AWS/GCP publish which region owns each prefix. That is the cloud itself telling you, and it beats every MaxMind-style guess. |
| **Latency floor as a falsifier** | Turns RTT from a vague hint into a hard bound: 1 ms per 100 km. It can only *disprove* claims — which is exactly what a confident answer needs. |
| **Anycast test** | Distinguishes "near the user" from "where the model runs" mechanically, with three probes. |
| **CT-log subdomain hunt** | Finds regional endpoints the docs never mention; `crt.sh` is public, cheap, and often the fastest path to a hidden `-eu`/`-jp` origin. |
| **Header forensics, with the edge-only rule** | Extracts real signal from `cf-ray`/`x-amz-cf-pop` while forbidding the one wrong conclusion they invite. |
| **Explicit four-state confidence** | Kills fake certainty. A regulator-facing answer needs "OPEN + the probe that settles it", not a confident guess. |
| **Mandatory falsification pass** | The difference between research and motivated reasoning. Every claim gets attacked before it ships. |
| **Stop condition + timebox** | Prevents both premature "good enough" and endless probing. |

## The line this stays behind

The prompt deliberately hands the agent the full passive grey-hat toolkit — CT logs, BGP/RPKI,
RDAP, PeeringDB, distributed probes, header forensics, public filings. All of it reads public data
about vendors you already contract with, which is ordinary due diligence, not intrusion.

What it refuses to do is cross from *observation* into *access*: no scanning, no exploitation, no
borrowed credentials, no social engineering, no auth walls, rate limits respected. That boundary is
also the practical one — scanning a provider's infrastructure is a contract violation and often a
crime, and it would poison the very evidence you're trying to produce.

Two honest limits worth knowing up front: for frontier API providers, the *exact facility* is often
not observable from outside — the defensible answer is a region or country with ANCHORED confidence,
not a street address. And the legal plane may be the real answer to the underlying question: a
provider's documented residency commitment is what determines where your data is processed, and the
network forensics exist to test whether that commitment is being honoured.

## The compact variant

For cheap or fast models — keeps the two non-negotiable moves.

````text
Determine where each fleet lane's model inference physically runs. Fleet: codex/gpt-6.1 sol,
opencode/minimax-3.1, antigravity/gemini-3.8-flash, pi/nemotron-ultra-550, grok/grok 4.7,
muse/muse wonder, dsh/deepseek-flash-4.1-107, plus coordinator Claude, broker Hermes, triage Jev.

Keep four things apart: the BASE URL the CLI calls (may be a router), the EDGE where TLS terminates
(CDN PoP - nearest to us, not the model), the ORIGIN where weights execute (the answer), and the LEGAL
entity with its residency commitment.

Resolve the chain: CLI -> base URL -> DNS/CNAME -> ASN -> serving entity -> cloud region -> facility.
Use only public data: dig/Resolve-DnsName, RDAP, whois.cymru.com, PeeringDB, crt.sh, AWS/GCP/Azure
published prefix tables, and globalping.io probes. A region encoded in the hostname, or a published
prefix's region field, beats any geoIP database. Ping from >=3 continents: uniformly low RTT means
anycast edge, not origin. RTT floor is ~1 ms per 100 km - if a measurement is below the floor for a
claimed origin, that claim is false.

No scanning, no borrowed credentials, no auth walls. Pace <=1 req/s.

Report per lane: serving entity, edge PoP, origin country/region/facility, confidence
(ANCHORED / CORROBORATED / INDICATED / OPEN), evidence command + output, and the strongest
counter-argument you tried. Label every INDICATED claim as such.
````

## Optional: orchestration recipe

If you run this as a fleet (fittingly):

1. **Fan out one subagent per lane** — each gets the full prompt plus its single lane row. No shared
   context, so no copy-paste contamination between answers.
2. **One verifier subagent** gets all ten cards and only the falsification pass (Step 6) plus the
   precedence rules. It is rewarded for killing claims, not confirming them.
3. **Merge** in the lead agent, resolving disagreements by precedence, not by majority.
