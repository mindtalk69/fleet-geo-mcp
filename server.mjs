#!/usr/bin/env node
// fleet-geo MCP server - stdio transport, zero dependencies.
//
// Tools return EVIDENCE plus a confidence state. They never invent a street address:
// "exact" means the precision field, backed by the evidence rows in the same answer.
import readline from 'node:readline';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { resolveHost } from './src/doh.mjs';
import { asnForIp, certSubdomains, cloudRangeFor, loadCloudRanges, peeringdbFor, probeEdgeHeaders, rdapFor, runMeasurement } from './src/sources.mjs';
import { analyzeLatency, assemble } from './src/classify.mjs';
import { isEntitled, loadCatalog, loadConfig, matchProvider, recordFact, staleness } from './src/catalog.mjs';
import { EDGE_ASNS } from './src/geo.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const SERVER = { name: 'fleet-geo', version: '1.1.0' };
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];

/** The fleet definition is data, not prose: adding a lane is a one-line edit. */
const loadFleet = () => JSON.parse(readFileSync(path.join(ROOT, 'fleet.json'), 'utf8'));

/* ------------------------------------------------------------------ helpers -- */

const hostOf = (s) => {
  try {
    return new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`).hostname;
  } catch {
    return String(s);
  }
};

async function factsForIp(ip) {
  const [asn, cloud] = await Promise.all([asnForIp(ip).catch(() => null), cloudRangeFor(ip).catch(() => null)]);
  const rdap = asn?.registry ? await rdapFor(ip, asn.registry).catch(() => null) : null;
  return { ip, asn, cloud, rdap, edge: Boolean(asn && EDGE_ASNS[asn.asn]) };
}

const chainCache = new Map();
const CHAIN_TTL = 10 * 60_000;

async function gatherChain(host, { maxIps = 3 } = {}) {
  const hit = chainCache.get(host);
  if (hit && Date.now() - hit.at < CHAIN_TTL) return hit.val;

  const chain = await resolveHost(host);
  const ips = chain.addresses.filter((a) => a.type === 'A').slice(0, maxIps);
  const ipFacts = [];
  for (const a of ips) ipFacts.push(await factsForIp(a.ip));

  const val = { chain, ipFacts };
  chainCache.set(host, { val, at: Date.now() });
  return val;
}

const RULES = `Precedence (highest first)
  1. provider documentation (recorded with record_fact, with URL + verbatim quote) / region encoded in the endpoint hostname
  2. the cloud's own published prefix metadata (AWS ip-ranges.json, gstatic cloud.json)
  3. PeeringDB facility for the serving ASN
  4. RDAP / ASN registration
  5. commercial geoIP databases
  6. latency inference

Planes - never merged
  CONTROL  the base URL the CLI actually calls (may be a router, not the model author)
  EDGE     where TLS terminates. Nearest to the caller. Not the model.
  ORIGIN   where weights execute and the prompt is processed. This is the answer.
  LEGAL    contracting entity, subprocessor list, residency commitment. What a DPO accepts.

Confidence
  ANCHORED      provider-documented (record_fact with a source), or the region is encoded in the endpoint hostname
  CORROBORATED  >=2 independent network sources agree
  INDICATED     one source only
  OPEN          no defensible evidence; the card names the probe that would settle it

Falsifier
  Fiber is ~200,000 km/s, so a round trip costs ~1 ms per 100 km. A measured RTT well
  below the floor for a claimed origin proves that claim wrong. Run it before believing
  any long-distance claim.

Growing the catalog
  Network evidence stops at the CDN edge for most APIs. The way to ANCHORED is
  documentation: read the provider's own page, then record_fact with source_url and a
  verbatim quote. Facts carry verification dates and the tool flags stale ones.`;

/* -------------------------------------------------------------------- tools -- */

const TOOLS = [
  {
    name: 'locate_model',
    title: 'Locate a model',
    description:
      'Resolve where a model\'s inference physically runs. Accepts a model id, a fleet lane/CLI name, or an explicit base_url. Returns a four-plane location card (control/edge/origin/legal), the serving chain, evidence rows with sources, a confidence state, contradictions, and the next probe that would tighten the answer. Re-derives everything from live DNS, ASN, cloud prefix tables and PeeringDB, so it tracks provider changes without redeploying.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Model id, e.g. "deepseek-flash-4.1-107" or "gpt-6.1 sol".' },
        lane: { type: 'string', description: 'Fleet lane or CLI name, e.g. "dsh", "codex", "grok".' },
        base_url: { type: 'string', description: 'The base URL the CLI is actually configured to call. Overrides the catalog default.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'fleet_status',
    title: 'Whole-fleet location sweep',
    description:
      'Run locate_model across every catalog provider that has a known API host and return one summary table: publisher, serving entity, edge operator, country/region, precision and confidence per lane. The one call to re-run whenever the fleet or a provider changes.',
    inputSchema: {
      type: 'object',
      properties: {
        lanes: { type: 'array', items: { type: 'string' }, description: 'Optional filter: lane/CLI names or provider keys.' },
        limit: { type: 'integer', minimum: 1, maximum: 20, description: 'Max providers to sweep (default 10).' },
        deep: { type: 'boolean', description: 'Include PeeringDB facility lookups (slower, more evidence).' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'trace_endpoint',
    title: 'Trace an endpoint',
    description:
      'Resolve one hostname into a serving chain: CNAME hops, addresses, ASN and org, registry RDAP, and the published cloud region of each address. Flags CDN/anycast addresses so an edge PoP is never mistaken for an origin.',
    inputSchema: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'Hostname or URL, e.g. "api.deepseek.com".' },
        max_ips: { type: 'integer', minimum: 1, maximum: 6, description: 'How many addresses to enrich (default 3).' },
      },
      required: ['host'],
      additionalProperties: false,
    },
  },
  {
    name: 'lookup_prefix',
    title: 'Look up an IP',
    description:
      'Identify a single address: ASN and org, the cloud\'s own published region for the prefix, RDAP registration, and PeeringDB facilities. The published cloud region outranks any geoIP database.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IPv4 address.' },
        include_facilities: { type: 'boolean', description: 'Include PeeringDB facilities (default true).' },
      },
      required: ['ip'],
      additionalProperties: false,
    },
  },
  {
    name: 'find_regional_endpoints',
    title: 'Find regional endpoints',
    description:
      'Search certificate transparency logs for subdomains of a domain and surface ones that look regional (-eu, -jp, -sg, -cn ...). Providers often run regional endpoints that no documentation mentions.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Apex domain, e.g. "openai.com".' },
        limit: { type: 'integer', minimum: 10, maximum: 500, description: 'Max names to return (default 200).' },
      },
      required: ['domain'],
      additionalProperties: false,
    },
  },
  {
    name: 'probe_latency',
    title: 'Probe latency and test the RTT floor',
    description:
      'Measure a host from distributed vantage points and test the physical RTT floor. Returns per-probe implied maximum distance, an anycast verdict, and a FALSIFIED verdict when a measurement is impossible for the claimed origin.',
    inputSchema: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'Hostname or IP to ping.' },
        expected_region: { type: 'string', description: 'Claimed cloud region, e.g. "ap-southeast-1".' },
        expected_country: { type: 'string', description: 'Claimed ISO country code, e.g. "CN".' },
        limit: { type: 'integer', minimum: 2, maximum: 20, description: 'Probe count (default 6).' },
        measurement_type: { type: 'string', enum: ['ping', 'traceroute'], description: 'Default ping.' },
      },
      required: ['host'],
      additionalProperties: false,
    },
  },
  {
    name: 'inspect_edge',
    title: 'Inspect edge headers',
    description:
      'Read response headers from an ENTITLED endpoint only (config.json allowlist) and report the TLS-terminating PoP. Explicitly an edge-plane fact: it never establishes where inference ran.',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'URL of an endpoint the fleet is entitled to call.' } },
      required: ['url'],
      additionalProperties: false,
    },
  },
  {
    name: 'record_fact',
    title: 'Record a documented fact',
    description:
      'Add a provider residency or facility fact to the catalog, citing a source URL and a verbatim quote. This is how the catalog learns: a verified fact becomes a tier-A anchor and lifts the matching card to ANCHORED. Pass publisher + match[] to add a provider that is not in the catalog yet.',
    inputSchema: {
      type: 'object',
      properties: {
        provider: { type: 'string', description: 'Catalog key, e.g. "deepseek".' },
        kind: { type: 'string', enum: ['residency', 'facility'], description: 'What kind of fact this is.' },
        region: { type: 'string', description: 'residency: region or country name, e.g. "us-east-1" or "CN".' },
        country: { type: 'string', description: '2-letter ISO country code, if known.' },
        name: { type: 'string', description: 'facility: site name, e.g. "Colossus".' },
        city: { type: 'string', description: 'facility: city.' },
        source_url: { type: 'string', description: 'URL of the provider page or filing that states this.' },
        quote: { type: 'string', description: 'Verbatim excerpt from that page supporting the fact (>=12 chars).' },
        verified_at: { type: 'string', description: 'ISO date you read it (default: today).' },
        publisher: { type: 'string', description: 'New provider only: the model publisher.' },
        match: { type: 'array', items: { type: 'string' }, description: 'New provider only: model-id regexes.' },
        api_hosts: { type: 'array', items: { type: 'string' }, description: 'New provider only: API hostnames.' },
      },
      required: ['provider', 'kind', 'source_url', 'quote'],
      additionalProperties: false,
    },
  },
  {
    name: 'explain_rules',
    title: 'Explain the rules',
    description: 'Return the source precedence, plane definitions, confidence states and the RTT falsifier used by every other tool.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

/* ---------------------------------------------------------------- handlers --- */

async function locateCore({ model = null, lane = null, baseUrl: explicitUrl = null, deep = false }) {
  const catalog = loadCatalog();
  // The operator thinks in lane ids ("W7"); resolve one to its CLI and model.
  const fleetLane = lane ? loadFleet().lanes.find((l) => l.lane.toLowerCase() === String(lane).toLowerCase()) : null;
  if (fleetLane) {
    lane = fleetLane.cli;
    model = model ?? fleetLane.model ?? null;
  }
  const provider = matchProvider(catalog, { model, lane });
  const baseUrl = explicitUrl ?? (provider?.apiHosts?.[0] ? `https://${provider.apiHosts[0]}` : null);

  if (!baseUrl) {
    return {
      error: 'NO_ENDPOINT',
      detail: 'No base_url given and the catalog has no default host for this model/lane. Read the CLI config (--help, config file, env vars) and pass base_url.',
      matched_provider: provider ? { key: provider.key, publisher: provider.publisher, matchedBy: provider.matchedBy } : null,
      nextProbes: ['Read the CLI config to find the real base URL, then re-run locate_model with base_url.'],
    };
  }

  const host = hostOf(baseUrl);
  const { chain, ipFacts } = await gatherChain(host);

  const nonEdge = ipFacts.filter((f) => f.asn && !EDGE_ASNS[f.asn.asn]);
  const facilities = deep && nonEdge.length ? await peeringdbFor(nonEdge[0].asn.asn).catch(() => null) : null;
  const servingEntity = facilities?.name ?? nonEdge[0]?.asn?.org ?? null;

  const card = assemble({
    subject: {
      input: model ?? lane ?? baseUrl,
      model,
      lane,
      baseUrl,
      host,
      publisher: provider?.publisher ?? null,
      servingEntity,
    },
    chain,
    ipFacts,
    facilities,
    catalogFacts: provider
      ? {
          publisher: provider.publisher,
          legalEntity: provider.legalEntity,
          residency: provider.residency,
          facilityAnchors: provider.facilityAnchors,
        }
      : null,
  });

  card.catalog = {
    matched: provider?.key ?? null,
    matchedBy: provider?.matchedBy ?? null,
    status: provider?.status ?? null,
    lastReviewed: catalog.lastReviewed,
    stale: provider ? staleness(catalog, provider) : [],
    notes: provider?.notes ?? null,
  };

  return card;
}

const toolLocateModel = (args) => locateCore({ model: args.model ?? null, lane: args.lane ?? null, baseUrl: args.base_url ?? null, deep: true });

async function toolFleetStatus(args) {
  const catalog = loadCatalog();
  const only = args.lanes?.length ? new Set(args.lanes.map((s) => String(s).toLowerCase())) : null;
  const targets = (catalog.providers ?? [])
    .filter((p) => (p.apiHosts ?? []).length > 0)
    .filter((p) => !only || only.has(p.key) || (p.laneClis ?? []).some((c) => only.has(String(c).toLowerCase())))
    .slice(0, args.limit ?? 10);

  const rows = [];
  const fleet = loadFleet();
  for (const p of targets) {
    const card = await locateCore({ lane: p.laneClis?.[0] ?? null, baseUrl: `https://${p.apiHosts[0]}`, deep: Boolean(args.deep) });
    const lanes = fleet.lanes.filter((l) => (p.laneClis ?? []).some((c) => c.toLowerCase() === l.cli.toLowerCase()));
    rows.push({
      provider: p.key,
      publisher: p.publisher,
      lane: p.laneClis?.[0] ?? null,
      lanes: lanes.map((l) => `${l.lane}:${l.cli}`),
      models: lanes.map((l) => l.model),
      host: p.apiHosts[0],
      servingEntity: card.subject?.servingEntity ?? null,
      edge: card.planes?.edge?.operator ?? null,
      country: card.location?.country ?? null,
      region: card.location?.region ?? null,
      precision: card.location?.precision ?? 'unknown',
      confidence: card.confidence ?? 'OPEN',
      why: card.confidenceWhy ?? null,
    });
  }

  const tally = (key) =>
    rows.reduce((acc, r) => {
      const k = r[key] ?? 'unknown';
      acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    }, {});

  return {
    summary: { swept: rows.length, byConfidence: tally('confidence'), byCountry: tally('country'), byEdge: tally('edge') },
    rows,
    interpretation:
      'Each row is independent. A shared CDN edge (Cloudflare, CloudFront) means the ORIGIN is hidden, not that two providers are in the same place. Rows that are OPEN need a documented fact (record_fact) or the provider\'s own regional endpoint.',
  };
}

async function toolTraceEndpoint(args) {
  const host = hostOf(args.host);
  const { chain, ipFacts } = await gatherChain(host, { maxIps: args.max_ips ?? 3 });
  return {
    host,
    chain,
    addresses: ipFacts,
    edgeAddresses: ipFacts.filter((f) => f.edge).map((f) => f.ip),
    originCandidates: ipFacts.filter((f) => !f.edge).map((f) => f.ip),
    interpretation:
      ipFacts.length === 0
        ? 'No addresses resolved.'
        : ipFacts.every((f) => f.edge)
          ? 'Every address belongs to an anycast/CDN network. This hostname reveals the EDGE only: the origin is behind it.'
          : 'At least one address is not a known CDN network; check whether its published cloud region matches the provider\'s documented residency.',
  };
}

async function toolLookupPrefix(args) {
  const facts = await factsForIp(args.ip);
  const facilities = args.include_facilities === false || !facts.asn ? null : await peeringdbFor(facts.asn.asn).catch(() => null);
  return {
    ...facts,
    facilities,
    note: facts.cloud
      ? `Published ${facts.cloud.cloud} prefix ${facts.cloud.prefix} => ${facts.cloud.region} (${facts.cloud.service}). This outranks any geoIP database.`
      : 'No published cloud prefix match: this address is not in a hyperscaler table, so ASN and PeeringDB carry the evidence.',
  };
}

async function toolFindRegionalEndpoints(args) {
  const r = await certSubdomains(args.domain, { limit: args.limit ?? 200 });
  return {
    domain: args.domain,
    ...r,
    interpretation: 'Regional-looking subdomains are leads, not anchors. Confirm each by resolving it and matching the published cloud region.',
  };
}

async function toolProbeLatency(args) {
  const limit = Math.min(Math.max(args.limit ?? 6, 2), 20);
  const target = args.host.includes('.') && !args.host.includes('/') ? args.host : hostOf(args.host);
  const m = await runMeasurement({ target, type: args.measurement_type ?? 'ping', limit });
  const analysis = analyzeLatency({
    measurements: m.results,
    origin: args.expected_region || args.expected_country ? { region: args.expected_region ?? null, country: args.expected_country ?? null } : null,
  });
  return { host: target, measurementId: m.id, ...analysis };
}

async function toolInspectEdge(args) {
  const host = hostOf(args.url);
  const gate = isEntitled(host);
  if (!gate.allowed) {
    return {
      error: 'NOT_ENTITLED',
      detail: gate.reason,
      nextProbes: ['Passive lookups (trace_endpoint, lookup_prefix) stay available for this host; add it to config.json entitledHosts only if the fleet is contracted to call it.'],
    };
  }
  const r = await probeEdgeHeaders(args.url);
  return { ...r, entitlement: gate.reason };
}

async function toolRecordFact(args) {
  return recordFact(args);
}

async function toolExplainRules() {
  const catalog = loadCatalog();
  const config = loadConfig();
  return {
    rules: RULES,
    catalog: { version: catalog.version, lastReviewed: catalog.lastReviewed, staleAfterDays: catalog.staleAfterDays, providers: catalog.providers.length },
    entitlement: { entitledHosts: config.entitledHosts, allowAnyHost: config.allowAnyHost },
    sources: [
      'DoH: dns.google / cloudflare-dns.com',
      'ASN: Team Cymru DNS (origin.asn.cymru.com, AS<asn>.asn.cymru.com)',
      'RDAP: registry-specific (arin, ripe, apnic, lacnic, afrinic)',
      'Cloud prefixes: AWS ip-ranges.json, gstatic cloud.json (Azure service tags unavailable: use the resource location instead)',
      'Facilities: PeeringDB netfac',
      'Certificates: crt.sh',
      'Probes: globalping.io',
    ],
  };
}

const HANDLERS = {
  locate_model: toolLocateModel,
  fleet_status: toolFleetStatus,
  trace_endpoint: toolTraceEndpoint,
  lookup_prefix: toolLookupPrefix,
  find_regional_endpoints: toolFindRegionalEndpoints,
  probe_latency: toolProbeLatency,
  inspect_edge: toolInspectEdge,
  record_fact: toolRecordFact,
  explain_rules: toolExplainRules,
};

async function callTool(name, args) {
  const fn = HANDLERS[name];
  if (!fn) return { isError: true, payload: { error: 'UNKNOWN_TOOL', detail: `no tool named ${name}`, available: Object.keys(HANDLERS) } };
  try {
    const payload = await fn(args ?? {});
    return { isError: Boolean(payload?.error), payload };
  } catch (e) {
    return { isError: true, payload: { error: 'TOOL_FAILED', tool: name, detail: e?.message ?? String(e) } };
  }
}

/* ------------------------------------------------------------ MCP transport -- */

const send = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
const failError = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

const RESOURCES = [
  { uri: 'geo://rules', name: 'geolocation rules', mimeType: 'text/plain', description: 'Precedence, planes, confidence states, RTT falsifier.' },
  { uri: 'geo://catalog', name: 'provider catalog', mimeType: 'application/json', description: 'The only hand-maintained data, with verification dates.' },
];

async function handle(msg) {
  const { id, method, params } = msg ?? {};
  const notify = id === undefined || id === null;

  switch (method) {
    case 'initialize': {
      const asked = params?.protocolVersion;
      const version = PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0];
      return reply(id, {
        protocolVersion: version,
        capabilities: { tools: { listChanged: false }, resources: { listChanged: false } },
        serverInfo: SERVER,
        instructions:
          'Evidence-first geolocation. Call explain_rules once, then fleet_status for the whole picture. Report each confidence state verbatim; never present an INDICATED claim as settled. When a lane is OPEN and the origin is behind a CDN, cite a provider page with record_fact rather than guessing.',
      });
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return undefined;
    case 'ping':
      return reply(id, {});
    case 'tools/list':
      return reply(id, { tools: TOOLS });
    case 'tools/call': {
      const { name, arguments: args } = params ?? {};
      const { isError, payload } = await callTool(name, args);
      return reply(id, {
        content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
        structuredContent: payload,
        isError,
      });
    }
    case 'resources/list':
      return reply(id, { resources: RESOURCES });
    case 'resources/read': {
      const uri = params?.uri;
      if (uri === 'geo://rules') return reply(id, { contents: [{ uri, mimeType: 'text/plain', text: RULES }] });
      if (uri === 'geo://catalog') {
        const c = loadCatalog();
        const { providers, ...rest } = c;
        return reply(id, {
          contents: [{ uri, mimeType: 'application/json', text: JSON.stringify({ ...rest, providers: providers.map(({ _re, ...p }) => p) }, null, 2) }],
        });
      }
      return failError(id, -32602, `unknown resource ${uri}`);
    }
    case 'prompts/list':
      return reply(id, { prompts: [] });
    case 'logging/setLevel':
      return reply(id, {});
    default:
      if (!notify) failError(id, -32601, `method not found: ${method}`);
      return undefined;
  }
}

async function serveStdio() {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const text = line.trim();
    if (!text) continue;
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      failError(null, -32700, 'parse error');
      continue;
    }
    const batch = Array.isArray(msg) ? msg : [msg];
    for (const m of batch) {
      try {
        await handle(m);
      } catch (e) {
        if (m?.id !== undefined && m?.id !== null) failError(m.id, -32603, e?.message ?? 'internal error');
      }
    }
  }
}

/* -------------------------------------------------------------------- CLI ----- */

const argv = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] ?? fallback : fallback;
};

if (argv.includes('--selftest')) {
  await import('./test/selftest.mjs');
} else if (argv.includes('--tool')) {
  const name = flag('tool');
  const args = JSON.parse(flag('args', '{}'));
  const { isError, payload } = await callTool(name, args);
  process.stdout.write(JSON.stringify({ isError, payload }, null, 2) + '\n');
  process.exit(isError ? 1 : 0);
} else if (argv.includes('--list-tools')) {
  process.stdout.write(JSON.stringify(TOOLS.map((t) => ({ name: t.name, description: t.description })), null, 2) + '\n');
} else {
  await loadCloudRanges().catch(() => {});
  await serveStdio();
}
