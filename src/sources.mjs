// Evidence sources. Every one is public, keyless, and read-only: DoH, Team Cymru's
// DNS ASN service, RDAP, published cloud prefix tables, PeeringDB, crt.sh, globalping.
// No TCP/43 whois, no port scanning, no authenticated calls except where the operator
// explicitly declares an entitled host.
import { resolveHost, txt } from './doh.mjs';
import { ipv4ToInt, parseCidr } from './geo.mjs';

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
  const n = ipv4ToInt(ip);
  if (n === null) return null; // IPv6 ASN lookup is out of scope for v1
  const rev = ip.split('.').reverse().join('.');
  await paced('cymru', 250);
  const rows = await txt(`${rev}.origin.asn.cymru.com`).catch(() => []);
  if (!rows.length) return null;
  const [asnRaw, prefix, country, registry, allocated] = rows[0].split('|').map((s) => s.trim());
  const asn = Number(asnRaw);
  if (!Number.isFinite(asn)) return null;

  await paced('cymru', 250);
  const nameRows = await txt(`AS${asn}.asn.cymru.com`).catch(() => []);
  const org = nameRows.length ? nameRows[0].split('|').map((s) => s.trim())[4] ?? null : null;
  return { asn, prefix, country, registry, allocated, org };
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
  const base = RDAP[String(registry || '').toLowerCase()] ?? RDAP.arin;
  await paced('rdap', 400);
  const j = await getJson(base + encodeURIComponent(ip), {
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
  const entries = [];
  const notes = [];

  const [aws, gcp] = await Promise.allSettled([
    getJson('https://ip-ranges.amazonaws.com/ip-ranges.json', { timeout: 20000 }),
    getJson('https://www.gstatic.com/ipranges/cloud.json', { timeout: 20000 }),
  ]);

  if (aws.status === 'fulfilled') {
    for (const p of aws.value.prefixes ?? []) {
      const c = parseCidr(p.ip_prefix);
      if (c) entries.push({ ...c, cloud: 'AWS', region: p.region, service: p.service, source: 'aws ip-ranges.json' });
    }
    notes.push(`aws ip-ranges.json ${aws.value.createDate ?? ''}`.trim());
  } else notes.push(`AWS ranges unavailable: ${aws.reason?.message}`);

  if (gcp.status === 'fulfilled') {
    for (const p of gcp.value.prefixes ?? []) {
      const cidr = p.ipv4Prefix;
      if (!cidr) continue;
      const c = parseCidr(cidr);
      if (c) entries.push({ ...c, cloud: 'GCP', region: p.scope, service: p.service, source: 'gstatic cloud.json' });
    }
    notes.push('gstatic cloud.json');
  } else notes.push(`GCP ranges unavailable: ${gcp.reason?.message}`);

  cloudCache = { entries, notes, loadedAt: new Date().toISOString() };
  cloudLoadedAt = Date.now();
  return cloudCache;
}

/** Longest-prefix match against the cloud's OWN published table. This outranks any geoIP DB. */
export async function cloudRangeFor(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return null;
  const { entries } = await loadCloudRanges();
  let best = null;
  for (const e of entries) {
    if (n >= e.start && n <= e.end && (!best || e.bits > best.bits)) best = e;
  }
  if (!best) return null;
  return { cloud: best.cloud, region: best.region, service: best.service, prefix: best.cidr, source: best.source };
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
  /\b(eu|us|ap|jp|sg|cn|hk|in|au|de|ie|uk|fr|ca|br|ae|kr|tw|id|sea|ams|fra|sfo|nyc|iad|sin|tok|syd)\b/i;

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

export async function probeEdgeHeaders(url, { timeout = 12000 } = {}) {
  const u = new URL(url.startsWith('http') ? url : `https://${url}`);
  await paced('edge', 500);
  const init = { method: 'GET', headers: { range: 'bytes=0-0', 'user-agent': 'fleet-geo-mcp/1.0' }, redirect: 'manual', signal: AbortSignal.timeout(timeout) };
  let res = await fetch(u, init);
  if (res.status === 405 || res.status === 501) {
    await paced('edge', 500);
    res = await fetch(u, { ...init, method: 'HEAD' });
  }
  const headers = {};
  for (const [k, v] of res.headers) {
    if (SECRET_HEADERS.test(k)) continue;
    headers[k.toLowerCase()] = v;
  }
  const cfRay = headers['cf-ray'] ?? null;
  const cfPop = cfRay ? cfRay.split('-').pop() : null;
  const cfPopCity = cfPop ? CLOUDFLARE_POP[cfPop] ?? null : null;
  const amzPop = headers['x-amz-cf-pop'] ?? null;

  return {
    url: u.toString(),
    status: res.status,
    edge: {
      vendor: cfRay ? 'Cloudflare' : amzPop ? 'AWS CloudFront' : headers['x-served-by'] ? 'Fastly' : headers.server ?? null,
      pop: cfPop ?? amzPop ?? headers['x-served-by'] ?? null,
      popCity: cfPopCity ?? (amzPop ? IATA[amzPop.slice(0, 3)] ?? null : null),
      server: headers.server ?? null,
      note: 'EDGE plane only: where TLS terminated, not where the model ran',
    },
    headers,
  };
}

// Cloudflare PoP IATA codes -> city. Partial on purpose: unknown codes are reported raw.
const CLOUDFLARE_POP = {
  SIN: 'Singapore', HKG: 'Hong Kong', NRT: 'Tokyo', KIX: 'Osaka', ICN: 'Seoul', TPE: 'Taipei',
  CGK: 'Jakarta', BOM: 'Mumbai', DEL: 'New Delhi', SYD: 'Sydney', MEL: 'Melbourne',
  FRA: 'Frankfurt', AMS: 'Amsterdam', LHR: 'London', CDG: 'Paris', DUB: 'Dublin', MAD: 'Madrid',
  MXP: 'Milan', WAW: 'Warsaw', ARN: 'Stockholm', IAD: 'Ashburn', EWR: 'Newark', ORD: 'Chicago',
  DFW: 'Dallas', LAX: 'Los Angeles', SEA: 'Seattle', SJC: 'San Jose', MIA: 'Miami', YYZ: 'Toronto',
  GRU: 'Sao Paulo', JNB: 'Johannesburg', DXB: 'Dubai', IST: 'Istanbul',
};

const IATA = { ...CLOUDFLARE_POP, IAD: 'Ashburn', CMH: 'Columbus', SFO: 'San Francisco' };

export { loadCloudRanges };
