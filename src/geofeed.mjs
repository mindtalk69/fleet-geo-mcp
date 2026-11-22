// RFC 8805 ("A Format for Self-Published IP Geolocation Feeds") + RFC 9092 / RFC 9632
// RDAP geofeed discovery, with mandatory §3.1 HTTPS-only transport, §3.2 authority
// verification against the linking RDAP IP block, §2.1.2 empty-location opt-out,
// and §3.4 HTTP Cache-Control/Expires refresh handling.
import { isLoopbackAddress, parseAddress, parseIpCidr } from './tcpip.mjs';
import { coordsFor } from './geo.mjs';
import { getNative } from './native.mjs';

const MIN_CACHE_MS = 60 * 60_000; // 1 hour
const DEFAULT_CACHE_MS = 24 * 60 * 60_000; // 24 hours
const MAX_CACHE_MS = 7 * 24 * 60 * 60_000; // 7 days (RFC 8805 §3.4 recommends <= weekly)
const MAX_FEED_BYTES = 8 * 1024 * 1024; // 8 MiB safety cap

const feedCache = new Map();

/** RFC 8805 §3.1: HTTPS-only, and block SSRF targets (loopback / private IP literals). */
export function isSafeGeofeedUrl(raw) {
  try {
    const u = new URL(String(raw ?? '').trim());
    if (u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase();
    if (!host || host === 'localhost' || host.endsWith('.local')) return false;
    const addr = parseAddress(host);
    if (addr && (addr.isLoopback || addr.isPrivate || addr.isUnspecified)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Discover a self-published RFC 8805 geofeed URL from an RDAP IP network response
 * (supports geofeedv1 extension, RDAP links rel="geofeed", and RFC 9092/9632 remarks).
 */
export function extractGeofeedUrl(rdap) {
  if (!rdap || typeof rdap !== 'object') return null;

  if (typeof rdap.geofeedv1_geofeed === 'string' && isSafeGeofeedUrl(rdap.geofeedv1_geofeed)) {
    return rdap.geofeedv1_geofeed.trim();
  }

  for (const link of rdap.links ?? []) {
    const rel = String(link?.rel ?? '').toLowerCase();
    const type = String(link?.type ?? '').toLowerCase();
    const href = String(link?.href ?? '').trim();
    if ((rel === 'geofeed' || type.includes('geofeed')) && isSafeGeofeedUrl(href)) {
      return href;
    }
  }

  const remarks = (rdap.remarks ?? []).flatMap((r) => r?.description ?? []);
  for (const line of remarks) {
    const m = String(line).match(/\bgeofeed\s*:?\s+(https:\/\/\S+)/i);
    if (m) {
      const candidate = m[1].replace(/[),.;]+$/, '');
      if (isSafeGeofeedUrl(candidate)) return candidate;
    }
  }

  return null;
}

/** Extract authorizing CIDR ranges / address bounds from an RDAP IP network object (raw or normalized). */
export function extractRdapScopes(rdap) {
  const scopes = [];
  if (!rdap || typeof rdap !== 'object') return scopes;

  for (const cidr of rdap.cidrs ?? []) {
    const parsed = parseIpCidr(cidr);
    if (parsed) scopes.push(parsed);
  }

  for (const c of rdap.cidr0_cidrs ?? []) {
    const prefix = c.v4prefix ?? c.v6prefix;
    const len = c.length;
    if (prefix && Number.isInteger(len)) {
      const parsed = parseIpCidr(`${prefix}/${len}`);
      if (parsed) scopes.push(parsed);
    }
  }

  if (!scopes.length && rdap.startAddress && rdap.endAddress) {
    const s = parseAddress(rdap.startAddress);
    const e = parseAddress(rdap.endAddress);
    if (s && e && s.family === e.family) {
      if (s.family === 'ipv4' && s.int <= e.int) {
        scopes.push({ family: 'ipv4', start: s.int, end: e.int, bits: 0, cidr: `${s.normalized}-${e.normalized}` });
      } else if (s.family === 'ipv6' && s.bigint <= e.bigint) {
        scopes.push({ family: 'ipv6', start: s.bigint, end: e.bigint, bits: 0, cidr: `${s.normalized}-${e.normalized}` });
      }
    }
  }

  return scopes;
}

/** RFC 8805 §3.2 Verification of Authority: child prefix must lie inside an authorizing RDAP block. */
export function isPrefixWithinScope(childCidr, scopes) {
  if (!childCidr || !Array.isArray(scopes) || scopes.length === 0) return false;
  return scopes.some(
    (parent) =>
      parent.family === childCidr.family &&
      childCidr.start >= parent.start &&
      childCidr.end <= parent.end,
  );
}

/** Parse one RFC 4180 CSV line (with RFC 8805 `#` comment stripping outside quotes). */
function parseCsvLine(line) {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = false;
      } else {
        cur += ch;
      }
    } else if (ch === '#') {
      break;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      fields.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  fields.push(cur.trim());
  return fields;
}

/**
 * Parse an RFC 8805 UTF-8 geolocation feed into IPv4 and IPv6 prefix entries.
 * Format: ip_prefix,alpha2code,region,city,postal_code
 */
export function parseGeofeedCsv(text) {
  const entriesV4 = [];
  const entriesV6 = [];
  let invalidLines = 0;
  let selfUrl = null;

  for (const rawLine of String(text ?? '').replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) {
      const sm = trimmed.match(/^#\s*geofeed\s*:?\s+(https:\/\/\S+)/i);
      if (sm && !selfUrl) selfUrl = sm[1];
      continue;
    }

    const cols = parseCsvLine(trimmed);
    const prefixRaw = cols[0] ?? '';
    if (!prefixRaw) continue;
    const parsed = parseIpCidr(prefixRaw);
    if (!parsed) { invalidLines++; continue; }

    const countryRaw = (cols[1] ?? '').toUpperCase();
    const country = /^[A-Z]{2}$/.test(countryRaw) ? countryRaw : null;
    const regionRaw = (cols[2] ?? '').toUpperCase();
    const region = /^[A-Z]{2}-[A-Z0-9]{1,3}$/.test(regionRaw) ? regionRaw : null;
    const city = (cols[3] ?? '').trim() || null;
    // RFC 8805 §2.1.1.5: postal_code is deprecated; accepted syntactically, not used for pinning.
    const noGeolocation = !country && !region && !city;

    const entry = { ...parsed, country, region, city, noGeolocation };
    if (parsed.family === 'ipv4') entriesV4.push(entry);
    else entriesV6.push(entry);
  }

  return { entriesV4, entriesV6, total: entriesV4.length + entriesV6.length, invalidLines, selfUrl };
}

/** RFC 8805 §3.4: Honor HTTP Cache-Control max-age or Expires, clamped to [1h, 7d]. */
export function parseCacheTtlMs(headers) {
  const cc = typeof headers?.get === 'function' ? headers.get('cache-control') : headers?.['cache-control'];
  if (cc) {
    const m = String(cc).match(/max-age=(\d+)/i);
    if (m) return Math.min(MAX_CACHE_MS, Math.max(MIN_CACHE_MS, Number(m[1]) * 1000));
  }
  const exp = typeof headers?.get === 'function' ? headers.get('expires') : headers?.expires;
  if (exp) {
    const ms = Date.parse(exp) - Date.now();
    if (Number.isFinite(ms) && ms > 0) return Math.min(MAX_CACHE_MS, Math.max(MIN_CACHE_MS, ms));
  }
  return DEFAULT_CACHE_MS;
}

function matchEntryInFeed(parsedFeed, addr, scopes) {
  const list = addr.family === 'ipv4' ? parsedFeed.entriesV4 : parsedFeed.entriesV6;
  const val = addr.family === 'ipv4' ? addr.int : addr.bigint;
  let best = null;
  let rejectedOutOfScope = 0;

  for (const e of list) {
    if (val < e.start || val > e.end) continue;
    if (scopes && scopes.length > 0 && !isPrefixWithinScope(e, scopes)) {
      rejectedOutOfScope++;
      continue;
    }
    if (!best || e.bits > best.bits) best = e;
  }
  return { best, rejectedOutOfScope };
}

/**
 * Fetch (with §3.4 caching) an RFC 8805 geofeed and match `ip` against it.
 * When `scopes` (from RDAP) are provided, §3.2 authority verification is strictly enforced.
 */
export async function lookupGeofeed(ip, { feedUrl, scopes = null, fetchImpl = fetch, timeout = 12000 } = {}) {
  const addr = parseAddress(ip);
  if (!addr || addr.isUnspecified || isLoopbackAddress(addr.normalized)) return null;
  if (!isSafeGeofeedUrl(feedUrl)) {
    return { error: 'INVALID_GEOFEED_URL', detail: 'RFC 8805 §3.1 requires a public HTTPS geofeed URL.', feedUrl };
  }

  let cached = feedCache.get(feedUrl);
  if (!cached || Date.now() >= cached.expiresAt) {
    const res = await fetchImpl(feedUrl, {
      headers: { 'user-agent': 'fleet-geo-mcp/1.2 (RFC8805 passive geofeed reader)' },
      signal: AbortSignal.timeout(timeout),
    });
    if (!res.ok) throw new Error(`geofeed HTTP ${res.status} from ${new URL(feedUrl).host}`);
    const body = await res.text();
    if (Buffer.byteLength(body, 'utf8') > MAX_FEED_BYTES) {
      throw new Error(`geofeed exceeds ${MAX_FEED_BYTES} byte limit`);
    }
    const parsed = parseGeofeedCsv(body);
    // Optional Rust N-API radix trie acceleration when no scope filtering is needed.
    let nativeTrie = null;
    const native = getNative();
    if (native?.PrefixTable && parsed.total >= 256) {
      try {
        const trie = new native.PrefixTable();
        const batch = [...parsed.entriesV4, ...parsed.entriesV6].map((e) => ({
          cidr: e.cidr,
          cloud: e.noGeolocation ? 'NONE' : 'RFC8805',
          region: e.region ?? '',
          service: e.city ?? '',
          source: e.country ?? '',
        }));
        trie.insertBatch(batch);
        nativeTrie = trie;
      } catch {
        nativeTrie = null;
      }
    }
    const ttlMs = parseCacheTtlMs(res.headers);
    cached = { parsed, nativeTrie, fetchedAt: new Date().toISOString(), expiresAt: Date.now() + ttlMs };
    feedCache.set(feedUrl, cached);
  }

  const authorityVerified = Boolean(scopes && scopes.length > 0);
  let best = null;
  let rejectedOutOfScope = 0;

  if (!authorityVerified && cached.nativeTrie) {
    const hit = cached.nativeTrie.lookup(addr.normalized);
    if (hit) {
      best = {
        cidr: hit.prefix,
        family: hit.family,
        country: hit.source || null,
        region: hit.region || null,
        city: hit.service || null,
        noGeolocation: hit.cloud === 'NONE',
      };
    }
  } else {
    ({ best, rejectedOutOfScope } = matchEntryInFeed(cached.parsed, addr, scopes));
  }

  if (!best) {
    return {
      matched: false,
      feedUrl,
      authorityVerified,
      rejectedOutOfScope,
      feedEntries: cached.parsed.total,
      fetchedAt: cached.fetchedAt,
    };
  }

  const coords = best.noGeolocation
    ? null
    : coordsFor({ city: best.city, region: best.region, country: best.country });

  return {
    matched: true,
    feedUrl,
    prefix: best.cidr,
    family: best.family,
    country: best.country,
    region: best.region,
    city: best.city,
    noGeolocation: best.noGeolocation,
    authorityVerified,
    rejectedOutOfScope,
    coords,
    fetchedAt: cached.fetchedAt,
  };
}
