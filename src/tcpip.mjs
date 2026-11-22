// Core TCP/IP & dual-stack connection MIB, modelled after RFC 1792
// ("TCP/IPX Connection MIB Specification", T. Sung, April 1995).
//
// RFC 1792 solved a classic MIB limitation: RFC 1213's tcpConnTable and udpTable
// hard-coded IPv4-only `IpAddress`, breaking whenever transport ran over another
// network layer (IPX, or in modern dual-stack hosts, IPv6). Its IESG note explicitly
// called for dual-stack implementation experience.
//
// We apply four RFC 1792 design rules to this MCP's TCP/IP layer:
//   1. Network-layer-typed addresses (IPv4, IPv6, IPX, unspecified) - never IPv4-only.
//   2. Full 4-tuple connection indexing: (localAddress, localPort, remAddress, remPort).
//   3. Complete RFC 793 / RFC 1792 TCP state machine (closed(1)..timeWait(11)) with
//      transient lifecycle tracking so short-lived connections aren't dropped.
//   4. Separation of active connections (>= synSent(3)) from unspecified-network
//      listeners (tcpUnspecConnTable, udpUnspecTable; state < synSent(3)), plus
//      first-class UDP endpoint tracking (QUIC/HTTP3, DNS).

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPX_RE = /^([0-9a-f]{8}):([0-9a-f]{12})$/i;
const MAX_IPV6 = (1n << 128n) - 1n;

/* ----------------------------------------------------------- IPv4 / IPv6 math */

export function ipv4ToInt(ip) {
  const m = IPV4_RE.exec(String(ip ?? '').trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function intToIpv4(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null;
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

/** Parse IPv6 address (with optional brackets or %zone) into an unsigned 128-bit BigInt. */
export function ipv6ToBigInt(raw) {
  let s = String(raw ?? '').trim().replace(/^\[|\]$/g, '').replace(/%[^/\s]+$/, '');
  if (!s || !s.includes(':')) return null;

  // Handle trailing embedded IPv4, e.g. ::ffff:192.0.2.128 or 64:ff9b::1.2.3.4
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToInt(tail);
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;

  const parseGroups = (part) => {
    if (!part) return [];
    const gs = part.split(':');
    const out = [];
    for (const g of gs) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  let groups;
  if (halves.length === 2) {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    groups = parseGroups(s);
    if (!groups || groups.length !== 8) return null;
  }

  let acc = 0n;
  for (const g of groups) acc = (acc << 16n) | BigInt(g);
  return acc;
}

/** Full 32-nibble lowercase hex representation of an IPv6 address (for origin6.asn.cymru.com). */
export function expandIpv6Hex(raw) {
  const n = typeof raw === 'bigint' ? raw : ipv6ToBigInt(raw);
  if (n === null || n < 0n || n > MAX_IPV6) return null;
  return n.toString(16).padStart(32, '0');
}

/** RFC 5952 canonical compressed IPv6 text from a BigInt or IPv6 string. */
export function compressIpv6(raw) {
  const n = typeof raw === 'bigint' ? raw : ipv6ToBigInt(raw);
  if (n === null || n < 0n || n > MAX_IPV6) return null;
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn));

  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }

  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

export function parseCidr(cidr) {
  const [ip, bitsRaw] = String(cidr ?? '').trim().split('/');
  const base = ipv4ToInt(ip);
  if (base === null) return null;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const start = (base & mask) >>> 0;
  return { family: 'ipv4', start, end: (start + (2 ** (32 - bits) - 1)) >>> 0, bits, cidr: String(cidr).trim() };
}

export function cidrContains(cidr, ip) {
  const n = typeof ip === 'number' ? ip : ipv4ToInt(ip);
  const c = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  if (n === null || !c || c.family === 'ipv6') return false;
  return n >= c.start && n <= c.end;
}

export function parseCidr6(cidr) {
  const [ip, bitsRaw] = String(cidr ?? '').trim().split('/');
  const base = ipv6ToBigInt(ip);
  if (base === null) return null;
  const bits = bitsRaw === undefined ? 128 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
  const shift = BigInt(128 - bits);
  const mask = bits === 0 ? 0n : (MAX_IPV6 >> shift) << shift;
  const start = base & mask;
  const hostSpan = shift === 0n ? 0n : (1n << shift) - 1n;
  return { family: 'ipv6', start, end: start | hostSpan, bits, cidr: String(cidr).trim() };
}

export function cidrContains6(cidr, ip) {
  const n = typeof ip === 'bigint' ? ip : ipv6ToBigInt(ip);
  const c = typeof cidr === 'string' ? parseCidr6(cidr) : cidr;
  if (n === null || !c || c.family !== 'ipv6') return false;
  return n >= c.start && n <= c.end;
}

export function parseIpCidr(cidr) {
  const s = String(cidr ?? '').trim();
  return s.includes(':') ? parseCidr6(s) : parseCidr(s);
}

export function ipCidrContains(cidr, ip) {
  const c = typeof cidr === 'string' ? parseIpCidr(cidr) : cidr;
  if (!c) return false;
  const addr = parseAddress(ip);
  if (!addr) return false;
  if (c.family === 'ipv4' && addr.family === 'ipv4') return addr.int >= c.start && addr.int <= c.end;
  if (c.family === 'ipv6' && addr.family === 'ipv6') return addr.bigint >= c.start && addr.bigint <= c.end;
  return false;
}

/* ------------------------------------------- Network-layer-typed addresses --- */

const isPrivateIpv4 = (n) =>
  (n >>> 24) === 10 ||
  ((n >>> 24) === 172 && ((n >>> 16) & 0xf0) === 16) ||
  ((n >>> 24) === 192 && ((n >>> 16) & 0xff) === 168) ||
  ((n >>> 24) === 169 && ((n >>> 16) & 0xff) === 254) ||
  ((n >>> 24) === 100 && ((n >>> 16) & 0xc0) === 64); // CGNAT / Tailscale 100.64.0.0/10

const isPrivateIpv6 = (n) => {
  const top16 = Number(n >> 112n);
  return (top16 & 0xfe00) === 0xfc00 || (top16 & 0xffc0) === 0xfe80; // ULA fc00::/7 or link-local fe80::/10
};

/**
 * Parse a network address into a network-layer-typed descriptor (RFC 1792 principle:
 * never conflate unspecified, IPv4, IPv6, and IPX addresses).
 * Unwraps IPv4-mapped IPv6 (::ffff:a.b.c.d) to canonical IPv4.
 */
export function parseAddress(raw) {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return null;
  if (trimmed === '*' || trimmed === '0.0.0.0' || trimmed === '::' || trimmed === '[::]') {
    const fam = trimmed === '0.0.0.0' ? 'ipv4' : trimmed === '::' || trimmed === '[::]' ? 'ipv6' : 'unspecified';
    return {
      family: fam,
      address: trimmed.replace(/^\[|\]$/g, ''),
      normalized: fam === 'ipv4' ? '0.0.0.0' : fam === 'ipv6' ? '::' : '*',
      isUnspecified: true,
      isLoopback: false,
      isPrivate: false,
      zone: null,
    };
  }
  if (trimmed.toLowerCase() === 'localhost') {
    return {
      family: 'ipv4',
      address: '127.0.0.1',
      normalized: '127.0.0.1',
      int: 0x7f000001,
      isUnspecified: false,
      isLoopback: true,
      isPrivate: true,
      zone: null,
    };
  }

  // RFC 1792 IpxAddress: nnnnnnnn:mmmmmmmmmmmm (4-octet network : 6-octet node)
  const ipx = IPX_RE.exec(trimmed);
  if (ipx) {
    const normalized = `${ipx[1].toLowerCase()}:${ipx[2].toLowerCase()}`;
    return {
      family: 'ipx',
      address: normalized,
      normalized,
      network: ipx[1].toLowerCase(),
      node: ipx[2].toLowerCase(),
      isUnspecified: normalized === '00000000:000000000000',
      isLoopback: false,
      isPrivate: true,
      zone: null,
    };
  }

  // Extract optional interface zone suffix (%lo, %eno1, %12) before or after brackets.
  let zone = null;
  let clean = trimmed;
  const zm = clean.match(/%([^/\]]+)$/);
  if (zm) {
    zone = zm[1];
    clean = clean.slice(0, zm.index);
  }
  clean = clean.replace(/^\[|\]$/g, '');
  const zmInner = clean.match(/%([^/]+)$/);
  if (zmInner) {
    zone = zone ?? zmInner[1];
    clean = clean.slice(0, zmInner.index);
  }

  const v4 = ipv4ToInt(clean);
  if (v4 !== null) {
    const normalized = intToIpv4(v4);
    const isUnspecified = v4 === 0;
    const isLoopback = (v4 >>> 24) === 127;
    return {
      family: 'ipv4',
      address: normalized,
      normalized,
      int: v4,
      isUnspecified,
      isLoopback,
      isPrivate: isLoopback || isPrivateIpv4(v4),
      zone,
    };
  }

  const v6 = ipv6ToBigInt(clean);
  if (v6 !== null) {
    // Unwrap IPv4-mapped IPv6 ::ffff:0:0/96 -> IPv4
    if ((v6 >> 32n) === 0xffffn) {
      const mapped = Number(v6 & 0xffffffffn);
      const normalized = intToIpv4(mapped);
      const isUnspecified = mapped === 0;
      const isLoopback = (mapped >>> 24) === 127;
      return {
        family: 'ipv4',
        address: normalized,
        normalized,
        int: mapped,
        mappedFromIpv6: true,
        isUnspecified,
        isLoopback,
        isPrivate: isLoopback || isPrivateIpv4(mapped),
        zone,
      };
    }
    const normalized = compressIpv6(v6);
    const isUnspecified = v6 === 0n;
    const isLoopback = v6 === 1n;
    return {
      family: 'ipv6',
      address: normalized,
      normalized,
      bigint: v6,
      expandedHex32: expandIpv6Hex(v6),
      isUnspecified,
      isLoopback,
      isPrivate: isLoopback || isPrivateIpv6(v6),
      zone,
    };
  }

  return null;
}

export const ipFamily = (ip) => parseAddress(ip)?.family ?? null;

export function isLoopbackAddress(ip) {
  const a = parseAddress(ip);
  return Boolean(a?.isLoopback);
}

export function isUnspecifiedAddress(ip) {
  const a = parseAddress(ip);
  return Boolean(a?.isUnspecified);
}

/** Parse a socket endpoint token like "10.0.0.5:443", "[::]:*", "[fe80::1]%eno1:546", "*:*". */
export function parseEndpoint(token) {
  const s = String(token ?? '').trim();
  const idx = s.lastIndexOf(':');
  if (idx < 0) return null;
  const addrRaw = s.slice(0, idx);
  const portRaw = s.slice(idx + 1);
  const wildcardPort = portRaw === '*' || portRaw === '0';
  const port = portRaw === '*' ? 0 : Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) return null;
  const addr = parseAddress(addrRaw);
  if (!addr) return null;
  return { ...addr, port, wildcardPort };
}

/* ------------------------------------------- RFC 1792 / RFC 793 TCP states --- */

export const TCP_STATE = Object.freeze({
  closed: 1,
  listen: 2,
  synSent: 3,
  synReceived: 4,
  established: 5,
  finWait1: 6,
  finWait2: 7,
  closeWait: 8,
  lastAck: 9,
  closing: 10,
  timeWait: 11,
  deleteTCB: 12,
});

export const TCP_STATE_NAME = Object.freeze(
  Object.fromEntries(Object.entries(TCP_STATE).map(([k, v]) => [v, k])),
);

const STATE_ALIASES = {
  CLOSED: 'closed',
  CLOSE: 'closed',
  UNCONN: 'closed',
  LISTEN: 'listen',
  LISTENING: 'listen',
  SYNSENT: 'synSent',
  SYN_SENT: 'synSent',
  'SYN-SENT': 'synSent',
  SYNRECV: 'synReceived',
  SYN_RECV: 'synReceived',
  SYN_RCVD: 'synReceived',
  SYN_RECEIVED: 'synReceived',
  'SYN-RECV': 'synReceived',
  'SYN-RECEIVED': 'synReceived',
  ESTAB: 'established',
  ESTABLISHED: 'established',
  FINWAIT1: 'finWait1',
  FIN_WAIT_1: 'finWait1',
  FIN_WAIT1: 'finWait1',
  'FIN-WAIT-1': 'finWait1',
  FINWAIT2: 'finWait2',
  FIN_WAIT_2: 'finWait2',
  FIN_WAIT2: 'finWait2',
  'FIN-WAIT-2': 'finWait2',
  CLOSEWAIT: 'closeWait',
  CLOSE_WAIT: 'closeWait',
  'CLOSE-WAIT': 'closeWait',
  LASTACK: 'lastAck',
  LAST_ACK: 'lastAck',
  'LAST-ACK': 'lastAck',
  CLOSING: 'closing',
  TIMEWAIT: 'timeWait',
  TIME_WAIT: 'timeWait',
  'TIME-WAIT': 'timeWait',
};

/** Normalize any OS TCP state token (ss, lsof, netstat) to RFC 1792 { name, code }. */
export function normalizeTcpState(raw) {
  const key = String(raw ?? '').trim().toUpperCase();
  const name = STATE_ALIASES[key] ?? null;
  if (!name) return null;
  return { name, code: TCP_STATE[name] };
}

/** RFC 1792: active TCP connection states are >= synSent(3) through timeWait(11). */
export const isActiveTcpState = (code) => Number.isInteger(code) && code >= TCP_STATE.synSent && code <= TCP_STATE.timeWait;

/** RFC 1792 tcpUnspecConnState: only closed(1) and listen(2) belong in the unspecified-network listener table. */
export const isListenerTcpState = (code) => code === TCP_STATE.closed || code === TCP_STATE.listen;

/* ----------------------------------------------- Cross-OS socket parsers ----- */

/**
 * Parse Linux `ss` output: supports both `ss -tnupHa` (TCP+UDP, all states, with
 * leading `tcp`/`udp` netid) and `ss -tnpH` (TCP without leading netid).
 */
export function parseSs(text) {
  const out = [];
  for (const raw of String(text ?? '').split('\n')) {
    const line = raw.trim();
    if (!line || /^(Netid|State)\s+/i.test(line)) continue;
    const cols = line.split(/\s+/);
    let idx = 0;
    let protocol = 'tcp';
    if (/^(tcp|udp|tcp6|udp6)$/i.test(cols[0])) {
      protocol = cols[0].toLowerCase().startsWith('udp') ? 'udp' : 'tcp';
      idx = 1;
    }
    const stateRaw = cols[idx];
    const localTok = cols[idx + 3];
    const remTok = cols[idx + 4];
    if (!stateRaw || !localTok || !remTok) continue;

    const local = parseEndpoint(localTok);
    const rem = parseEndpoint(remTok);
    if (!local || !rem) continue;

    const st = protocol === 'tcp' ? normalizeTcpState(stateRaw) : { name: rem.isUnspecified && rem.wildcardPort ? 'listen' : 'established', code: rem.isUnspecified && rem.wildcardPort ? TCP_STATE.listen : TCP_STATE.established };
    if (!st) continue;

    const rest = cols.slice(idx + 5).join(' ');
    const procMatches = [...rest.matchAll(/\("([^"]*)",pid=(\d+)/g)];
    const family = !rem.isUnspecified && rem.family !== 'unspecified'
      ? rem.family
      : local.family !== 'unspecified' ? local.family : 'unspecified';

    const makeRow = (pid, proc) => ({
      protocol,
      family,
      state: st.name,
      stateCode: st.code,
      localIp: local.normalized,
      localPort: local.port,
      ip: rem.normalized,
      port: rem.port,
      localUnspecified: local.isUnspecified,
      remUnspecified: rem.isUnspecified || rem.wildcardPort,
      pid,
      process: proc,
    });

    if (procMatches.length) {
      for (const m of procMatches) out.push(makeRow(Number(m[2]), m[1] || null));
    } else {
      const pidOnly = rest.match(/pid=(\d+)/);
      out.push(makeRow(pidOnly ? Number(pidOnly[1]) : null, null));
    }
  }
  return out;
}

/**
 * Parse macOS `lsof` field output: supports both `lsof -nP -iTCP -iUDP -F pnPT`
 * (protocol + TCP state) and legacy `lsof -nP -iTCP -sTCP:ESTABLISHED -F pn`.
 */
export function parseLsof(text) {
  const out = [];
  let pid = null;
  let proc = null;
  let cur = null;

  const flush = () => {
    if (!cur || !cur.name) return;
    const protocol = (cur.protocol ?? 'TCP').toLowerCase().startsWith('udp') ? 'udp' : 'tcp';
    const parts = cur.name.split('->');
    const local = parseEndpoint(parts[0]);
    const rem = parts[1] ? parseEndpoint(parts[1]) : { family: 'unspecified', normalized: '*', port: 0, isUnspecified: true, wildcardPort: true };
    if (!local || !rem) return;

    const st = protocol === 'tcp'
      ? normalizeTcpState(cur.state ?? (parts[1] ? 'ESTABLISHED' : 'LISTEN'))
      : { name: parts[1] ? 'established' : 'listen', code: parts[1] ? TCP_STATE.established : TCP_STATE.listen };
    if (!st) return;

    const family = !rem.isUnspecified && rem.family !== 'unspecified'
      ? rem.family
      : local.family !== 'unspecified' ? local.family : 'unspecified';

    out.push({
      protocol,
      family,
      state: st.name,
      stateCode: st.code,
      localIp: local.normalized,
      localPort: local.port,
      ip: rem.normalized,
      port: rem.port,
      localUnspecified: local.isUnspecified,
      remUnspecified: rem.isUnspecified || rem.wildcardPort,
      pid,
      process: proc,
    });
    cur = null;
  };

  for (const line of String(text ?? '').split('\n')) {
    if (!line) continue;
    const tag = line[0];
    const val = line.slice(1);
    if (tag === 'p') { flush(); pid = Number(val); proc = null; }
    else if (tag === 'c') { proc = val || null; }
    else if (tag === 'f') { flush(); cur = { fd: val }; }
    else if (tag === 'P') { if (!cur) cur = {}; cur.protocol = val; }
    else if (tag === 'n') {
      if (cur && cur.name) flush();
      if (!cur) cur = {};
      cur.name = val;
    } else if (tag === 'T' && val.startsWith('ST=')) {
      if (!cur) cur = {};
      cur.state = val.slice(3);
    }
  }
  flush();
  return out;
}

/**
 * Parse Windows `netstat -ano` output (TCP all states + UDP, IPv4 + IPv6).
 */
export function parseNetstat(text) {
  const out = [];
  for (const raw of String(text ?? '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const cols = line.split(/\s+/);
    const protoRaw = cols[0]?.toUpperCase();
    if (protoRaw === 'TCP' && cols.length >= 5) {
      const local = parseEndpoint(cols[1]);
      const rem = parseEndpoint(cols[2]);
      const st = normalizeTcpState(cols[3]);
      const pid = Number(cols[4]);
      if (!local || !rem || !st || !Number.isFinite(pid)) continue;
      const family = !rem.isUnspecified && rem.family !== 'unspecified'
        ? rem.family
        : local.family !== 'unspecified' ? local.family : 'unspecified';
      out.push({
        protocol: 'tcp',
        family,
        state: st.name,
        stateCode: st.code,
        localIp: local.normalized,
        localPort: local.port,
        ip: rem.normalized,
        port: rem.port,
        localUnspecified: local.isUnspecified,
        remUnspecified: rem.isUnspecified || rem.wildcardPort,
        pid,
        process: null,
      });
    } else if (protoRaw === 'UDP' && cols.length >= 4) {
      const local = parseEndpoint(cols[1]);
      const rem = parseEndpoint(cols[2]);
      const pid = Number(cols[3]);
      if (!local || !rem || !Number.isFinite(pid)) continue;
      const unconnected = rem.isUnspecified || rem.wildcardPort;
      const family = !unconnected && rem.family !== 'unspecified'
        ? rem.family
        : local.family !== 'unspecified' ? local.family : 'unspecified';
      out.push({
        protocol: 'udp',
        family,
        state: unconnected ? 'listen' : 'established',
        stateCode: unconnected ? TCP_STATE.listen : TCP_STATE.established,
        localIp: local.normalized,
        localPort: local.port,
        ip: rem.normalized,
        port: rem.port,
        localUnspecified: local.isUnspecified,
        remUnspecified: unconnected,
        pid,
        process: null,
      });
    }
  }
  return out;
}

/* ------------------------------------------- RFC 1792 4-Table Connection MIB - */

/**
 * Dual-stack connection & listener MIB modelled on RFC 1792's four tables:
 *   - tcpConnTable        active TCP connections (>= synSent), 4-tuple + family indexed
 *   - tcpUnspecConnTable  wildcard-address TCP listeners (< synSent), localPort indexed
 *   - tcpListeners        interface-bound TCP listeners (e.g. 127.0.0.1:8787)
 *   - udpTable            connected UDP endpoints (QUIC/HTTP3, DNS) & bound UDP listeners
 *   - udpUnspecTable      wildcard-address UDP listeners, localPort indexed
 *
 * Implements RFC 1792 transient entry lifecycle: when a previously active TCP 4-tuple
 * disappears from a later snapshot, its transition to closed(1) is recorded while the
 * observation history stays available for the session audit.
 */
export class ConnectionMib {
  constructor() {
    this.tcpConnTable = new Map();
    this.tcpUnspecConnTable = new Map();
    this.tcpListeners = new Map();
    this.udpTable = new Map();
    this.udpUnspecTable = new Map();
  }

  ingest(entries, { now = new Date().toISOString(), markMissingClosed = false } = {}) {
    const seenActiveTcp = new Set();

    for (const e of entries ?? []) {
      if (e.protocol === 'tcp') {
        if (isListenerTcpState(e.stateCode) || (e.remUnspecified && e.stateCode === TCP_STATE.listen)) {
          if (e.localUnspecified) {
            // RFC 1792 tcpUnspecConnTable: INDEX { tcpUnspecConnLocalPort }
            const key = String(e.localPort);
            const prev = this.tcpUnspecConnTable.get(key);
            if (!prev) {
              this.tcpUnspecConnTable.set(key, {
                localPort: e.localPort,
                state: e.state,
                stateCode: e.stateCode,
                families: e.family !== 'unspecified' ? [e.family] : [],
                pids: e.pid != null ? [e.pid] : [],
                process: e.process ?? null,
                firstSeen: now,
                lastSeen: now,
              });
            } else {
              prev.lastSeen = now;
              prev.state = e.state;
              prev.stateCode = e.stateCode;
              if (e.family !== 'unspecified' && !prev.families.includes(e.family)) prev.families.push(e.family);
              if (e.pid != null && !prev.pids.includes(e.pid)) prev.pids.push(e.pid);
              if (!prev.process && e.process) prev.process = e.process;
            }
          } else {
            const key = `${e.family}|${e.localIp}:${e.localPort}`;
            const prev = this.tcpListeners.get(key);
            if (!prev) {
              this.tcpListeners.set(key, {
                family: e.family,
                localAddress: e.localIp,
                localPort: e.localPort,
                state: e.state,
                stateCode: e.stateCode,
                pid: e.pid ?? null,
                process: e.process ?? null,
                firstSeen: now,
                lastSeen: now,
              });
            } else {
              prev.lastSeen = now;
              if (prev.pid == null && e.pid != null) prev.pid = e.pid;
              if (!prev.process && e.process) prev.process = e.process;
            }
          }
          continue;
        }

        if (isActiveTcpState(e.stateCode) && !e.remUnspecified) {
          // RFC 1792 tcpIpxConnTable generalized to dual-stack:
          // INDEX { family, localAddress, localPort, remAddress, remPort }
          const key = `${e.family}|${e.localIp}:${e.localPort}|${e.ip}:${e.port}`;
          seenActiveTcp.add(key);
          const prev = this.tcpConnTable.get(key);
          if (!prev) {
            this.tcpConnTable.set(key, {
              protocol: 'tcp',
              family: e.family,
              localAddress: e.localIp,
              localPort: e.localPort,
              remAddress: e.ip,
              remPort: e.port,
              state: e.state,
              stateCode: e.stateCode,
              states: [e.state],
              pid: e.pid ?? null,
              process: e.process ?? null,
              firstSeen: now,
              lastSeen: now,
              closedAt: null,
            });
          } else {
            prev.lastSeen = now;
            prev.closedAt = null;
            if (prev.state !== e.state) {
              prev.state = e.state;
              prev.stateCode = e.stateCode;
              prev.states.push(e.state);
            }
            if (prev.pid == null && e.pid != null) prev.pid = e.pid;
            if (!prev.process && e.process) prev.process = e.process;
          }
        }
      } else if (e.protocol === 'udp') {
        if (e.remUnspecified && e.localUnspecified) {
          // RFC 1792 udpUnspecTable: INDEX { udpUnspecLocalPort }
          const key = String(e.localPort);
          const prev = this.udpUnspecTable.get(key);
          if (!prev) {
            this.udpUnspecTable.set(key, {
              localPort: e.localPort,
              families: e.family !== 'unspecified' ? [e.family] : [],
              pids: e.pid != null ? [e.pid] : [],
              process: e.process ?? null,
              firstSeen: now,
              lastSeen: now,
            });
          } else {
            prev.lastSeen = now;
            if (e.family !== 'unspecified' && !prev.families.includes(e.family)) prev.families.push(e.family);
            if (e.pid != null && !prev.pids.includes(e.pid)) prev.pids.push(e.pid);
            if (!prev.process && e.process) prev.process = e.process;
          }
        } else {
          const key = e.remUnspecified
            ? `${e.family}|${e.localIp}:${e.localPort}`
            : `${e.family}|${e.localIp}:${e.localPort}|${e.ip}:${e.port}`;
          const prev = this.udpTable.get(key);
          if (!prev) {
            this.udpTable.set(key, {
              protocol: 'udp',
              family: e.family,
              localAddress: e.localIp,
              localPort: e.localPort,
              remAddress: e.remUnspecified ? null : e.ip,
              remPort: e.remUnspecified ? null : e.port,
              pid: e.pid ?? null,
              process: e.process ?? null,
              firstSeen: now,
              lastSeen: now,
            });
          } else {
            prev.lastSeen = now;
            if (prev.pid == null && e.pid != null) prev.pid = e.pid;
            if (!prev.process && e.process) prev.process = e.process;
          }
        }
      }
    }

    if (markMissingClosed) {
      for (const [key, row] of this.tcpConnTable) {
        if (!seenActiveTcp.has(key) && row.stateCode !== TCP_STATE.closed) {
          row.state = 'closed';
          row.stateCode = TCP_STATE.closed;
          if (row.states[row.states.length - 1] !== 'closed') row.states.push('closed');
          row.closedAt = now;
        }
      }
    }
  }

  /** Deduplicated remote (non-unspecified) endpoints across active TCP and connected UDP. */
  remoteEndpoints({ includeLoopback = false } = {}) {
    const out = new Map();
    const record = (row) => {
      if (!row.remAddress) return;
      if (!includeLoopback && isLoopbackAddress(row.remAddress)) return;
      const key = `${row.protocol}|${row.remAddress}:${row.remPort}`;
      const prev = out.get(key);
      if (!prev) {
        out.set(key, {
          protocol: row.protocol,
          family: row.family,
          ip: row.remAddress,
          port: row.remPort,
          localAddress: row.localAddress,
          localPort: row.localPort,
          pid: row.pid,
          process: row.process,
          states: row.states ? [...row.states] : [row.protocol === 'udp' ? 'connected' : 'established'],
          firstSeen: row.firstSeen,
          lastSeen: row.lastSeen,
        });
      } else {
        prev.lastSeen = row.lastSeen;
        for (const s of row.states ?? []) if (!prev.states.includes(s)) prev.states.push(s);
      }
    };
    for (const r of this.tcpConnTable.values()) record(r);
    for (const r of this.udpTable.values()) if (r.remAddress) record(r);
    return [...out.values()];
  }

  snapshot() {
    const tcpConn = [...this.tcpConnTable.values()];
    const tcpUnspec = [...this.tcpUnspecConnTable.values()];
    const tcpBoundListeners = [...this.tcpListeners.values()];
    const udpAll = [...this.udpTable.values()];
    const udpUnspec = [...this.udpUnspecTable.values()];

    const byFamily = {};
    const byState = {};
    for (const r of [...tcpConn, ...udpAll.filter((u) => u.remAddress)]) {
      byFamily[r.family] = (byFamily[r.family] ?? 0) + 1;
      const st = r.state ?? 'udp-connected';
      byState[st] = (byState[st] ?? 0) + 1;
    }

    return {
      rfc: 'RFC 1792 (dual-stack TCP/UDP connection & unspecified-network listener MIB)',
      summary: {
        tcpConnections: tcpConn.length,
        tcpUnspecListeners: tcpUnspec.length,
        tcpBoundListeners: tcpBoundListeners.length,
        udpEndpoints: udpAll.length,
        udpUnspecListeners: udpUnspec.length,
        byFamily,
        byState,
      },
      tcpConnTable: tcpConn,
      tcpUnspecConnTable: tcpUnspec,
      tcpListeners: tcpBoundListeners,
      udpTable: udpAll,
      udpUnspecTable: udpUnspec,
    };
  }
}
