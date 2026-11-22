// Evidence sources. Every one is public, keyless, and read-only: DoH, Team Cymru's
// DNS ASN service, RDAP, published cloud prefix tables, PeeringDB, crt.sh, globalping.
// No TCP/43 whois, no port scanning, no authenticated calls except where the operator
// explicitly declares an entitled host.
import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { resolveHost, txt } from './doh.mjs';
import { IATA_COORDS, coordsFor, parseAddress, parseCidr, parseCidr6, round } from './geo.mjs';
import { extractGeofeedUrl, extractRdapScopes } from './geofeed.mjs';
import { getNative } from './native.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Polite pacing, one lane per upstream source. These services are shared, free,
// and rate-limited; hammering them is both rude and self-sabotaging.
const lastCall = new Map();
async function paced(key, minIntervalMs) {
  const prev = lastCall.get(key) ?? 0;
  const wait = prev + minIntervalMs - Date.now();
  if (wait > 0) await sleep(wait);
  lastCall.set(key, Date.now());
}

async function getJson(url, { timeout = 12000, headers = {} } = {}) {
  const res = await fetch(url, {
    headers: { 'user-agent': 'fleet-geo-mcp/1.0 (passive public-data geolocation)', ...headers },
    signal: AbortSignal.timeout(timeout),
  });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} from ${new URL(url).host}`);
    err.status = res.status;
    throw err;
  }
  const ct = res.headers.get('content-type') ?? '';
  const body = await res.text();
  if (!ct.includes('json') && !/^[[{]/.test(body.trim())) {
    throw new Error(`non-JSON response from ${new URL(url).host} (${ct || 'no content-type'})`);
  }
  return JSON.parse(body);
}

/* ---------------------------------------------------------------- ASN (Cymru) */

export async function asnForIp(ip) {
  const addr = parseAddress(ip);
  if (!addr || addr.isUnspecified || addr.isLoopback) return null;

  let queryName;
  if (addr.family === 'ipv4') {
    queryName = `${addr.normalized.split('.').reverse().join('.')}.origin.asn.cymru.com`;
  } else if (addr.family === 'ipv6') {
    queryName = `${addr.expandedHex32.split('').reverse().join('.')}.origin6.asn.cymru.com`;
  } else {
    return null;
  }

  await paced('cymru', 250);
  const rows = await txt(queryName).catch(() => []);
  if (!rows.length) return null;
  const [asnRaw, prefix, country, registry, allocated] = rows[0].split('|').map((s) => s.trim());
  // Multi-origin prefixes can return space-separated ASNs; take the primary origin ASN.
  const asn = Number(String(asnRaw ?? '').split(/\s+/)[0]);
  if (!Number.isFinite(asn)) return null;

  await paced('cymru', 250);
  const nameRows = await txt(`AS${asn}.asn.cymru.com`).catch(() => []);
  const org = nameRows.length ? nameRows[0].split('|').map((s) => s.trim())[4] ?? null : null;
  return { asn, prefix, country, registry, allocated, org, family: addr.family };
}

/* ------------------------------------------------------------------- RDAP ---- */

const RDAP = {
  arin: 'https://rdap.arin.net/registry/ip/',
  ripencc: 'https://rdap.db.ripe.net/ip/',
  apnic: 'https://rdap.apnic.net/ip/',
  lacnic: 'https://rdap.lacnic.net/rdap/ip/',
  afrinic: 'https://rdap.afrinic.net/rdap/ip/',
};

export async function rdapFor(ip, registry) {
  const addr = parseAddress(ip);
  const target = addr?.normalized ?? String(ip).trim();
  const base = RDAP[String(registry || '').toLowerCase()] ?? RDAP.arin;
  await paced('rdap', 400);
  const j = await getJson(base + encodeURIComponent(target), {
    timeout: 12000,
    headers: { accept: 'application/rdap+json' },
  });
  const entityNames = (j.entities ?? [])
    .map((e) => e.vcardArray?.[1]?.find?.((f) => f[0] === 'fn')?.[3])
    .filter(Boolean);
  return {
    handle: j.handle ?? null,
    name: j.name ?? null,
    country: j.country ?? null,
    type: j.type ?? null,
    startAddress: j.startAddress ?? null,
    endAddress: j.endAddress ?? null,
    cidrs: (j.cidr0_cidrs ?? [])
      .map((c) => ((c.v4prefix ?? c.v6prefix) && Number.isInteger(c.length) ? `${c.v4prefix ?? c.v6prefix}/${c.length}` : null))
      .filter(Boolean),
    geofeedUrl: extractGeofeedUrl(j),
    entities: [...new Set(entityNames)].slice(0, 6),
    remarks: (j.remarks ?? []).flatMap((r) => r.description ?? []).slice(0, 3),
  };
}

/* ------------------------------------------- Published cloud prefix tables ---- */

let cloudCache = null;
let cloudLoadedAt = 0;
const CLOUD_TTL = 6 * 60 * 60_000;

async function loadCloudRanges() {
  if (cloudCache && Date.now() - cloudLoadedAt < CLOUD_TTL) return cloudCache;
  const entriesV4 = [];
  const entriesV6 = [];
  const notes = [];

  const [aws, gcp] = await Promise.allSettled([
    getJson('https://ip-ranges.amazonaws.com/ip-ranges.json', { timeout: 20000 }),
    getJson('https://www.gstatic.com/ipranges/cloud.json', { timeout: 20000 }),
  ]);

  if (aws.status === 'fulfilled') {
    for (const p of aws.value.prefixes ?? []) {
      const c = parseCidr(p.ip_prefix);
      if (c) entriesV4.push({ ...c, cloud: 'AWS', region: p.region, service: p.service, source: 'aws ip-ranges.json' });
    }
    for (const p of aws.value.ipv6_prefixes ?? []) {
      const c = parseCidr6(p.ipv6_prefix);
      if (c) entriesV6.push({ ...c, cloud: 'AWS', region: p.region, service: p.service, source: 'aws ip-ranges.json' });
    }
    notes.push(`aws ip-ranges.json ${aws.value.createDate ?? ''}`.trim());
  } else notes.push(`AWS ranges unavailable: ${aws.reason?.message}`);

  if (gcp.status === 'fulfilled') {
    for (const p of gcp.value.prefixes ?? []) {
      if (p.ipv4Prefix) {
        const c = parseCidr(p.ipv4Prefix);
        if (c) entriesV4.push({ ...c, cloud: 'GCP', region: p.scope, service: p.service, source: 'gstatic cloud.json' });
      }
      if (p.ipv6Prefix) {
        const c = parseCidr6(p.ipv6Prefix);
        if (c) entriesV6.push({ ...c, cloud: 'GCP', region: p.scope, service: p.service, source: 'gstatic cloud.json' });
      }
    }
    notes.push('gstatic cloud.json');
  } else notes.push(`GCP ranges unavailable: ${gcp.reason?.message}`);

  let nativeTrie = null;
  const native = getNative();
  if (native?.PrefixTable) {
    try {
      const trie = new native.PrefixTable();
      const batch = [
        ...entriesV4.map((e) => ({ cidr: e.cidr, cloud: e.cloud, region: e.region, service: e.service, source: e.source })),
        ...entriesV6.map((e) => ({ cidr: e.cidr, cloud: e.cloud, region: e.region, service: e.service, source: e.source })),
      ];
      trie.insertBatch(batch);
      nativeTrie = trie;
    } catch {
      nativeTrie = null;
    }
  }

  cloudCache = { entries: entriesV4, entriesV4, entriesV6, nativeTrie, notes, loadedAt: new Date().toISOString() };
  cloudLoadedAt = Date.now();
  return cloudCache;
}

/** Longest-prefix match against the cloud's OWN published IPv4 + IPv6 tables. Outranks any geoIP DB. */
export async function cloudRangeFor(ip) {
  const addr = parseAddress(ip);
  if (!addr || addr.isUnspecified || addr.isLoopback) return null;
  const { entriesV4, entriesV6, nativeTrie } = await loadCloudRanges();

  if (nativeTrie) {
    return nativeTrie.lookup(addr.normalized) ?? null;
  }

  let best = null;
  if (addr.family === 'ipv4') {
    const n = addr.int;
    for (const e of entriesV4) {
      if (n >= e.start && n <= e.end && (!best || e.bits > best.bits)) best = e;
    }
  } else if (addr.family === 'ipv6') {
    const n = addr.bigint;
    for (const e of entriesV6) {
      if (n >= e.start && n <= e.end && (!best || e.bits > best.bits)) best = e;
    }
  }
  if (!best) return null;
  return { cloud: best.cloud, region: best.region, service: best.service, prefix: best.cidr, family: best.family, source: best.source };
}

/* --------------------------------------------------------------- PeeringDB --- */

export async function peeringdbFor(asn, { limit = 12 } = {}) {
  await paced('peeringdb', 600);
  const net = await getJson(`https://peeringdb.com/api/net?asn=${encodeURIComponent(asn)}`, { timeout: 15000 });
  const row = net.data?.[0];
  if (!row) return null;
  await paced('peeringdb', 600);
  const fac = await getJson(`https://peeringdb.com/api/netfac?net_id=${row.id}`, { timeout: 20000 });
  const facilities = (fac.data ?? []).map((f) => ({
    name: f.name,
    city: f.city,
    country: f.country,
    lat: f.latitude ?? null,
    lon: f.longitude ?? null,
  }));
  const countries = [...new Set(facilities.map((f) => f.country).filter(Boolean))];
  return {
    name: row.name ?? null,
    asn,
    facilityCount: facilities.length,
    countries,
    facilities: facilities.slice(0, limit),
  };
}

/* ----------------------------------------------------------------- crt.sh ---- */

const REGION_HINT =
  /\b(eu|us|ap|jp|sg|cn|hk|in|au|de|ie|uk|fr|ca|br|ae|kr|tw|id|sea|ams|fra|sfo|nyc|iad|sin|tok|syd|origin|direct|regional)\b/i;

export async function certSubdomains(domain, { limit = 200 } = {}) {
  await paced('crtsh', 1000);
  const url = `https://crt.sh/?q=${encodeURIComponent('%25.' + domain)}&output=json`;
  const res = await fetch(url, {
    headers: { 'user-agent': 'fleet-geo-mcp/1.0' },
    signal: AbortSignal.timeout(25000),
  });
  if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
  const body = await res.text();
  if (!/^\s*[[{]/.test(body)) throw new Error('crt.sh returned HTML (busy or rate-limited) - retry later');
  const rows = JSON.parse(body);
  const names = [...new Set(rows.flatMap((e) => String(e.name_value ?? '').split('\n')))].filter(
    (n) => n && n.includes(domain) && !n.startsWith('*'),
  );
  const hints = names.filter((n) => REGION_HINT.test(n));
  return { total: names.length, names: names.slice(0, limit), regionHints: hints.slice(0, 40) };
}

/* -------------------------------------------------------------- globalping --- */

export async function runMeasurement({ target, type = 'ping', limit = 6, locations = null, timeoutMs = 45000 }) {
  const payload = {
    type,
    target,
    limit,
    locations: locations ?? [{ magic: 'World' }],
    measurementOptions: type === 'ping' ? { packets: 4 } : { hops: 12, protocol: 'ICMP' },
  };
  await paced('globalping', 1500);
  const res = await fetch('https://api.globalping.io/v1/measurements', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'fleet-geo-mcp/1.0' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`globalping create HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const job = await res.json();

  const deadline = Date.now() + timeoutMs;
  let m = job;
  while (Date.now() < deadline) {
    if (m.status === 'finished') break;
    if (m.status === 'failed') throw new Error('globalping measurement failed');
    await sleep(2000);
    const r = await fetch(`https://api.globalping.io/v1/measurements/${job.id}`, {
      headers: { 'user-agent': 'fleet-geo-mcp/1.0' },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) throw new Error(`globalping poll HTTP ${r.status}`);
    m = await r.json();
  }

  const results = (m.results ?? []).map((r) => {
    const p = r.probe ?? {};
    const st = r.result?.stats ?? {};
    let avg = st.avg ?? null;
    if (avg === null && typeof r.result?.rawOutput === 'string') {
      const hit = /rtt min\/avg\/max\/mdev = [\d.]+\/([\d.]+)\//.exec(r.result.rawOutput);
      if (hit) avg = Number(hit[1]);
    }
    return {
      city: p.city ?? null,
      country: p.country ?? null,
      continent: p.continent ?? null,
      network: p.network ?? null,
      asn: p.asn ?? null,
      lat: p.latitude ?? null,
      lon: p.longitude ?? null,
      avgRttMs: avg === null ? null : Number(avg),
      resolvedAddress: r.result?.resolvedAddress ?? null,
      status: r.result?.status ?? null,
    };
  });

  return { id: job.id ?? null, status: m.status ?? 'unknown', target, type, results };
}

/* ------------------------------------------------------- Entitled host probe -- */

const SECRET_HEADERS = /^(authorization|proxy-authorization|x-api-key|api-key|cookie|set-cookie)$/i;

/** Low-level timed HTTP(S) probe: captures RFC 9293 TCP SYN->SYN-ACK RTT vs TLS vs TTFB. */
function timedHttpRequest(u, method, timeout) {
  return new Promise((resolve, reject) => {
    const mod = u.protocol === 'http:' ? http : https;
    const tStart = performance.now();
    let tLookup = null;
    let tConnect = null;
    let tTls = null;
    let remoteAddress = null;

    const req = mod.request(
      u,
      {
        method,
        headers: { range: 'bytes=0-0', 'user-agent': 'fleet-geo-mcp/1.2', connection: 'close' },
        agent: false, // fresh TCP handshake so SYN->SYN-ACK RTT is measured honestly
        timeout,
      },
      (res) => {
        const tFirstByte = performance.now();
        res.resume(); // discard body; headers + timing only
        const headers = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (SECRET_HEADERS.test(k)) continue;
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
        }
        const dnsMs = tLookup !== null ? tLookup - tStart : null;
        const tcpConnectBase = tLookup ?? tStart;
        const edgeTcpRttMs = tConnect !== null ? tConnect - tcpConnectBase : null;
        const tlsMs = tTls !== null && tConnect !== null ? tTls - tConnect : null;
        const requestSentAt = tTls ?? tConnect ?? tStart;
        const httpRttMs = tFirstByte - requestSentAt;
        const ttfbMs = tFirstByte - tStart;
        const backendDeltaMs = edgeTcpRttMs !== null ? Math.max(0, httpRttMs - edgeTcpRttMs) : null;

        resolve({
          status: res.statusCode ?? 0,
          headers,
          remoteIp: remoteAddress ? (parseAddress(remoteAddress)?.normalized ?? remoteAddress) : null,
          timing: {
            dnsMs: round(dnsMs, 2),
            edgeTcpRttMs: round(edgeTcpRttMs, 2),
            tlsMs: round(tlsMs, 2),
            httpRttMs: round(httpRttMs, 2),
            ttfbMs: round(ttfbMs, 2),
            backendDeltaMs: round(backendDeltaMs, 2),
            impliedEdgeMaxDistanceKm: edgeTcpRttMs !== null ? Math.round(edgeTcpRttMs * 100) : null,
            impliedBackendMaxDistanceKm: backendDeltaMs !== null ? Math.round(backendDeltaMs * 100) : null,
            note: 'edgeTcpRttMs is SYN->SYN-ACK to the TLS edge; backendDeltaMs mixes edge->origin transit and server processing time (upper bound only).',
          },
        });
      },
    );

    req.on('socket', (sock) => {
      sock.on('lookup', () => { tLookup = performance.now(); });
      sock.on('connect', () => {
        tConnect = performance.now();
        remoteAddress = sock.remoteAddress ?? null;
      });
      sock.on('secureConnect', () => { tTls = performance.now(); });
    });
    req.on('timeout', () => req.destroy(new Error(`edge probe timeout after ${timeout}ms`)));
    req.on('error', reject);
    req.end();
  });
}

/** Extract a 3-letter IATA airport PoP code from common CDN edge headers. */
export function extractEdgePop(headers = {}) {
  const cfRay = headers['cf-ray'] ?? null;
  if (cfRay) {
    const code = cfRay.split('-').pop()?.toUpperCase();
    return { vendor: 'Cloudflare', raw: cfRay, iata: /^[A-Z]{3}$/.test(code) ? code : null, header: 'cf-ray' };
  }
  const amzPop = headers['x-amz-cf-pop'] ?? null;
  if (amzPop) {
    const code = amzPop.slice(0, 3).toUpperCase();
    return { vendor: 'AWS CloudFront', raw: amzPop, iata: /^[A-Z]{3}$/.test(code) ? code : null, header: 'x-amz-cf-pop' };
  }
  const fastly = headers['x-served-by'] ?? null;
  if (fastly) {
    const m = fastly.match(/-([A-Z]{3})\b/);
    return { vendor: 'Fastly', raw: fastly, iata: m ? m[1] : null, header: 'x-served-by' };
  }
  const vercel = headers['x-vercel-id'] ?? null;
  if (vercel) {
    const m = vercel.match(/^([a-z]{3})\d?::/i);
    return { vendor: 'Vercel Edge', raw: vercel, iata: m ? m[1].toUpperCase() : null, header: 'x-vercel-id' };
  }
  const fly = headers['fly-region'] ?? null;
  if (fly) {
    const code = fly.trim().slice(0, 3).toUpperCase();
    return { vendor: 'Fly.io', raw: fly, iata: /^[A-Z]{3}$/.test(code) ? code : null, header: 'fly-region' };
  }
  const edgeLoc = headers['x-edge-location'] ?? null;
  if (edgeLoc) {
    const code = edgeLoc.trim().slice(0, 3).toUpperCase();
    return { vendor: headers.server ?? 'CDN Edge', raw: edgeLoc, iata: /^[A-Z]{3}$/.test(code) ? code : null, header: 'x-edge-location' };
  }
  if (headers['x-azure-ref']) {
    return { vendor: 'Azure Front Door', raw: headers['x-azure-ref'], iata: null, header: 'x-azure-ref' };
  }
  return { vendor: headers.server ?? null, raw: null, iata: null, header: null };
}

export async function probeEdgeHeaders(url, { timeout = 12000 } = {}) {
  const u = new URL(url.startsWith('http') ? url : `https://${url}`);
  await paced('edge', 500);
  let res = await timedHttpRequest(u, 'GET', timeout);
  if (res.status === 405 || res.status === 501) {
    await paced('edge', 500);
    res = await timedHttpRequest(u, 'HEAD', timeout);
  }
  const { headers } = res;
  const pop = extractEdgePop(headers);
  const popCoords = pop.iata ? coordsFor({ iata: pop.iata }) : null;

  const originHints = {};
  for (const k of ['x-supabase-region', 'x-cloud-region', 'x-region', 'server-timing']) {
    if (headers[k]) originHints[k] = headers[k];
  }

  return {
    url: u.toString(),
    status: res.status,
    remoteIp: res.remoteIp,
    timing: res.timing,
    edge: {
      vendor: pop.vendor,
      header: pop.header,
      pop: pop.iata ?? pop.raw,
      popRaw: pop.raw,
      popCity: popCoords?.place ?? (pop.iata ? IATA_COORDS[pop.iata]?.place ?? null : null),
      popCountry: popCoords?.country ?? null,
      server: headers.server ?? null,
      note: 'EDGE plane only: where TLS terminated, not where the model ran',
    },
    edgePin: popCoords
      ? {
          lat: popCoords.lat,
          lon: popCoords.lon,
          place: popCoords.place,
          country: popCoords.country,
          iata: pop.iata,
          plane: 'EDGE',
          precision: 'pop',
          source: `${pop.vendor} ${pop.header}`,
        }
      : null,
    originHints: Object.keys(originHints).length ? originHints : null,
    headers,
  };
}

export { loadCloudRanges };
