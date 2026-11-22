// DNS over HTTPS resolver.
//
// Why DoH instead of node:dns: the platform resolver on this host times out on TXT
// records, and ISP resolvers can return poisoned or geo-steered answers. Every DNS
// fact used as evidence must come from a resolver we can name and re-query.
const RESOLVERS = [
  { name: 'google', base: 'https://dns.google/resolve', hdr: { accept: 'application/dns-json' }, timeout: 8000 },
  { name: 'cloudflare', base: 'https://cloudflare-dns.com/dns-query', hdr: { accept: 'application/dns-json' }, timeout: 8000 },
];

const TYPE_NAMES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
const CACHE_MS = 5 * 60_000;
const cache = new Map();

async function dohQuery(name, type, r) {
  const url = `${r.base}?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: r.hdr, signal: AbortSignal.timeout(r.timeout) });
  if (!res.ok) throw new Error(`${r.name} HTTP ${res.status}`);
  const j = await res.json();
  // RFC 1035 RCODE 2 (SERVFAIL) / 5 (REFUSED) is a resolver failure, not NXDOMAIN:
  // fail over to the next DoH resolver instead of caching an empty answer.
  if (j.Status === 2 || j.Status === 5) throw new Error(`${r.name} DNS RCODE ${j.Status}`);
  return {
    resolver: r.name,
    status: j.Status ?? 0,
    answers: (j.Answer ?? []).map((a) => ({
      name: String(a.name || '').replace(/\.$/, ''),
      type: TYPE_NAMES[a.type] ?? String(a.type),
      data: String(a.data || ''),
      ttl: a.TTL,
    })),
  };
}

export async function query(name, type = 'A') {
  const key = `${type}|${name}`.toLowerCase();
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return hit.val;
  let lastErr;
  for (const r of RESOLVERS) {
    try {
      const val = await dohQuery(name, type, r);
      cache.set(key, { val, exp: Date.now() + CACHE_MS });
      return val;
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`DoH ${type} ${name} failed: ${lastErr?.message ?? 'unknown'}`);
}

/** Follow the CNAME chain, then collect A/AAAA records. Every hop is evidence. */
export async function resolveHost(input) {
  let host = String(input).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  const hops = [];
  const seen = new Set();
  let resolver = null;

  for (let i = 0; i < 10; i++) {
    const c = await query(host, 'CNAME').catch(() => null);
    if (c?.resolver) resolver = c.resolver;
    const target = c?.answers.find((a) => a.type === 'CNAME')?.data?.replace(/\.$/, '');
    if (!target || target === host || seen.has(target)) break;
    seen.add(host);
    hops.push({ from: host, to: target });
    host = target;
  }

  const addresses = [];
  for (const t of ['A', 'AAAA']) {
    const r = await query(host, t).catch(() => null);
    if (r?.resolver) resolver = r.resolver;
    for (const a of r?.answers ?? []) {
      if (a.type === 'A' || a.type === 'AAAA') addresses.push({ ip: a.data, type: a.type, ttl: a.ttl });
    }
  }

  return { requested: String(input), finalHost: host, hops, addresses, resolver };
}

/** TXT record joined into single strings (SPF-style records arrive as fragments). */
export async function txt(name) {
  const r = await query(name, 'TXT');
  return r.answers.filter((a) => a.type === 'TXT').map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
}
