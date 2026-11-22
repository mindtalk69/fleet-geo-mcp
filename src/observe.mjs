// observe_endpoints - watch which hosts a CLI actually connects to.
//
// This settles the CONTROL plane (the base URL a CLI really calls). It never settles the
// ORIGIN: every packet we can see ends at the TLS edge. Nothing is decrypted - the hostname
// comes from the CONNECT line, the cleartext TLS SNI, or the DNS question.
//
// Layers, all without root:
//   proxy    a logging HTTP CONNECT proxy (pure Node, every OS) for CLIs that honour HTTPS_PROXY
//   sockets  RFC 1792-modeled dual-stack TCP/UDP connection & listener MIB from the OS socket
//            table: ss -tnupHa (Linux), lsof -nP -iTCP -iUDP (macOS), netstat -ano (Windows).
//            Captures IPv4 + IPv6, all TCP states (SYN-SENT..TIME-WAIT), UDP/QUIC, and separates
//            unspecified-network listeners from active connections.
//   strace   Linux, when installed: SNI + DNS names + every connect, bound to remote IP.
import http from 'node:http';
import net from 'node:net';
import { spawn, execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  ConnectionMib,
  isLoopbackAddress,
  isUnspecifiedAddress,
  parseAddress,
  parseLsof,
  parseNetstat,
  parseSs,
} from './tcpip.mjs';

export { ConnectionMib, parseLsof, parseNetstat, parseSs };

/* ---------------------------------------------------------------- parsers ---- */

/** Hostname from a TLS ClientHello record, or null. Cleartext by design of TLS 1.2/1.3. */
export function parseClientHelloSni(buf) {
  try {
    if (buf.length < 43 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
    let p = 9 + 2 + 32; // record hdr(5) + hs hdr(4) + version(2) + random(32)
    p += 1 + buf[p]; // session id
    p += 2 + buf.readUInt16BE(p); // cipher suites
    p += 1 + buf[p]; // compression methods
    const end = Math.min(buf.length, p + 2 + buf.readUInt16BE(p));
    p += 2;
    while (p + 4 <= end) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      p += 4;
      if (type === 0x0000) {
        // server_name: list len(2), name type(1), name len(2), name
        if (buf[p + 2] !== 0) return null;
        const n = buf.readUInt16BE(p + 3);
        const host = buf.subarray(p + 5, p + 5 + n).toString('ascii');
        return /^[a-z0-9.-]+$/i.test(host) ? host.toLowerCase() : null;
      }
      p += len;
    }
  } catch { /* truncated capture */ }
  return null;
}

/** Question name of a DNS query (UDP payload), or null. */
export function parseDnsQuestion(buf) {
  try {
    if (buf.length < 17) return null;
    const flags = buf.readUInt16BE(2);
    if (flags & 0x8000) return null; // a response, not a query
    if (buf.readUInt16BE(4) !== 1) return null; // exactly one question
    const labels = [];
    let p = 12;
    while (buf[p] !== 0) {
      const n = buf[p];
      if (n > 63 || p + 1 + n > buf.length) return null;
      labels.push(buf.subarray(p + 1, p + 1 + n).toString('ascii'));
      p += 1 + n;
    }
    const name = labels.join('.').toLowerCase();
    return /^[a-z0-9_.-]+\.[a-z0-9-]+$/.test(name) ? name : null;
  } catch { return null; }
}

const unescapeStrace = (s) => Buffer.from(s.replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');

/**
 * Parse `strace -f -yy -xx -s N -e trace=network,write,writev` output.
 * Returns connects, SNI hostnames and DNS questions, each bound to the remote endpoint.
 */
export function parseStrace(text) {
  const connects = [];
  const sni = [];
  const dns = [];
  for (const raw of String(text).split('\n')) {
    // -xx hex-escapes every string, including the address inside inet_addr("...").
    const line = raw.replace(/(inet_addr\(|inet_pton\(AF_INET6, )"((?:\\x[0-9a-f]{2})+)"/gi, (_, fn, h) => `${fn}"${unescapeStrace(h).toString('latin1')}"`);
    const c = line.match(/\bconnect\(\d+(?:<([^>]*)>)?, \{sa_family=(AF_INET6?), sin6?_port=htons\((\d+)\),.*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")/);
    if (c) {
      const rawIp = c[4] ?? c[5];
      if (!rawIp || rawIp.startsWith('/')) continue;
      const addr = parseAddress(rawIp);
      const ip = addr?.normalized ?? rawIp;
      if (addr?.isUnspecified || ip === '0.0.0.0' || ip === '::') continue;
      const sockTag = String(c[1] ?? '').toUpperCase();
      const protocol = sockTag.startsWith('UDP') ? 'udp' : 'tcp';
      const family = addr?.family ?? (c[2] === 'AF_INET6' ? 'ipv6' : 'ipv4');
      connects.push({ ip, port: Number(c[3]), protocol, family });
      continue;
    }
    const w = line.match(/\b(?:write|writev|sendto|sendmsg|sendmmsg|send)\(\d+<(TCP6?|UDP6?):\[(.*?)->\[?([0-9a-f.:%]+?)\]?:(\d+)\]>/i);
    if (!w) continue;
    const blobs = [...line.matchAll(/"((?:\\x[0-9a-f]{2})+)"/gi)].map((m) => unescapeStrace(m[1]));
    if (!blobs.length) continue;
    const payload = Buffer.concat(blobs);
    const addr = parseAddress(w[3]);
    const remote = { ip: addr?.normalized ?? w[3], port: Number(w[4]) };
    if (w[1].startsWith('TCP')) {
      const host = parseClientHelloSni(payload);
      if (host) sni.push({ ...remote, host });
    } else if (remote.port === 53) {
      // sendmmsg carries the A and AAAA queries as separate datagrams in one line.
      for (const b of blobs) {
        const name = parseDnsQuestion(b);
        if (name) dns.push({ ...remote, name });
      }
    }
  }
  return { connects, sni, dns };
}

/** pid -> ppid rows from `ps -A -o pid=,ppid=` or Windows CSV (ProcessId,ParentProcessId). */
export function parseProcessTable(text) {
  const rows = [];
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.replace(/"/g, '').trim().match(/^(\d+)[\s,]+(\d+)$/);
    if (m) rows.push({ pid: Number(m[1]), ppid: Number(m[2]) });
  }
  return rows;
}

export function descendants(rows, root) {
  const kids = new Map();
  for (const r of rows) kids.set(r.ppid, [...(kids.get(r.ppid) ?? []), r.pid]);
  const seen = new Set([root]);
  const stack = [root];
  while (stack.length) for (const k of kids.get(stack.pop()) ?? []) if (!seen.has(k)) { seen.add(k); stack.push(k); }
  return seen;
}

const isLoopback = (ip) => isLoopbackAddress(ip) || isUnspecifiedAddress(ip);

/* ------------------------------------------------------------------ proxy ---- */

/** Logging CONNECT/HTTP proxy. Bytes are forwarded untouched; only host, port and volume are kept. */
export function startProxy() {
  const tunnels = [];
  // Every socket we open, so close() can end lingering keep-alive tunnels: server.close()
  // alone waits for them forever when a CLI leaves a helper process connected.
  const open = new Set();
  const track = (s) => { open.add(s); s.on('close', () => open.delete(s)); return s; };
  const server = http.createServer((req, res) => {
    // Plain-HTTP absolute-form request (local endpoints such as http://127.0.0.1:8787).
    let url;
    try { url = new URL(req.url); } catch { res.writeHead(400).end(); return; }
    const rec = { host: url.hostname.toLowerCase(), port: Number(url.port || 80), scheme: 'http', at: new Date().toISOString(), up: 0, down: 0 };
    tunnels.push(rec);
    const fwd = http.request({ host: url.hostname, port: rec.port, method: req.method, path: url.pathname + url.search, headers: req.headers }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.on('data', (d) => { rec.down += d.length; });
      r.pipe(res);
    });
    fwd.on('error', () => { rec.error = 'upstream'; res.writeHead(502).end(); });
    req.on('data', (d) => { rec.up += d.length; });
    req.pipe(fwd);
  });
  server.on('connect', (req, client, head) => {
    const [host, port = '443'] = String(req.url).split(/:(?=\d+$)/);
    const rec = { host: host.replace(/^\[|\]$/g, '').toLowerCase(), port: Number(port), scheme: 'connect', at: new Date().toISOString(), up: head.length, down: 0 };
    tunnels.push(rec);
    track(client);
    const upstream = track(net.connect(rec.port, rec.host, () => {
      rec.ip = upstream.remoteAddress?.replace(/^::ffff:/, '') ?? null;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      client.pipe(upstream);
      upstream.pipe(client);
    }));
    client.on('data', (d) => {
      rec.up += d.length;
      if (!rec.sni) rec.sni = parseClientHelloSni(d) ?? undefined;
    });
    upstream.on('data', (d) => { rec.down += d.length; });
    const close = () => { client.destroy(); upstream.destroy(); };
    upstream.on('error', () => { rec.error = 'upstream'; close(); });
    client.on('error', close);
  });
  server.on('connection', track);
  const close = () => new Promise((r) => {
    server.close(() => r());
    for (const s of open) s.destroy();
    server.closeAllConnections?.();
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, tunnels, close })));
}

/* -------------------------------------------------------------- OS sockets --- */

const run = (cmd, args, timeout = 5000) =>
  new Promise((resolve) => execFile(cmd, args, { timeout, maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (err, stdout) => resolve(err && !stdout ? '' : String(stdout))));

/**
 * Snapshot dual-stack TCP (all RFC 1792 states) and UDP sockets/listeners on any OS.
 */
export async function socketSnapshot(platform = process.platform) {
  if (platform === 'linux') return parseSs(await run('ss', ['-tnupHa']));
  if (platform === 'darwin') return parseLsof(await run('lsof', ['-nP', '-iTCP', '-iUDP', '-F', 'pcfnPT']));
  if (platform === 'win32') return parseNetstat(await run('netstat', ['-ano']));
  return [];
}

export async function processTable(platform = process.platform) {
  if (platform === 'win32') {
    return parseProcessTable(await run('powershell', ['-NoProfile', '-Command',
      'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Csv -NoTypeInformation']));
  }
  return parseProcessTable(await run('ps', ['-A', '-o', 'pid=,ppid=']));
}

/* ---------------------------------------------------------------- runner ----- */

const PROMPT = 'Reply with exactly: OK';

/** The argv a lane runs on this platform, with fixtures substituted. Pure: no side effects. */
export function laneCommand(lane, platform = process.platform, vars = {}) {
  const spec = lane?.observe;
  if (!spec) return null;
  const argv = spec.argvByPlatform?.[platform] ?? spec.argv;
  if (!Array.isArray(argv) || !argv.length) return null;
  const sub = (s) => String(s).replace(/\{(\w+)\}/g, (m, k) => (k === 'prompt' ? PROMPT : vars[k] ?? m));
  return { argv: argv.map(sub), env: Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, sub(v)])), fixture: spec.fixture ?? null };
}

/** A throwaway git repo with one commit touching a test file - enough for jev to ask a model. */
function gitFixture(dir) {
  const git = (...a) => new Promise((res, rej) => execFile('git', ['-C', dir, ...a], (e, o) => (e ? rej(e) : res(String(o).trim()))));
  return (async () => {
    await git('init', '-q');
    await git('-c', 'user.name=observe', '-c', 'user.email=observe@localhost', 'commit', '-q', '--allow-empty', '-m', 'base');
    const base = await git('rev-parse', 'HEAD');
    mkdirSync(path.join(dir, 'test'), { recursive: true });
    writeFileSync(path.join(dir, 'test', 'probe.test.js'), "test('probe', () => {});\n");
    await git('add', '.');
    await git('-c', 'user.name=observe', '-c', 'user.email=observe@localhost', 'commit', '-q', '-m', 'probe');
    const head = await git('rev-parse', 'HEAD');
    const brief = path.join(dir, '..', 'brief.md');
    writeFileSync(brief, '# probe\n\nFiles: test/probe.test.js\n');
    return { repo: dir, base, head, brief };
  })();
}

function killTree(child, platform) {
  if (!child.pid) return;
  try {
    if (platform === 'win32') execFile('taskkill', ['/T', '/F', '/PID', String(child.pid)], () => {});
    else process.kill(-child.pid, 'SIGKILL');
  } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } }
}

const quoteWin = (a) => (/[\s"&|<>^]/.test(a) ? `"${String(a).replace(/"/g, '\\"')}"` : a);

/**
 * Run one lane's probe command and record every outbound connection it makes.
 * deps are injectable for tests (spawnImpl, platform, useStrace).
 */
export async function observeLane(lane, { timeoutMs = 120_000, platform = process.platform, useStrace, pollMs = 250 } = {}) {
  const work = mkdtempSync(path.join(tmpdir(), 'fleet-geo-observe-'));
  const cwd = path.join(work, 'cwd');
  mkdirSync(cwd);
  const startedAt = new Date().toISOString();
  try {
    const vars = { cwd, tmp: work };
    if (lane.observe?.fixture === 'git') Object.assign(vars, await gitFixture(cwd));
    const cmd = laneCommand(lane, platform, vars);
    if (!cmd) return { lane: lane.lane, cli: lane.cli, error: 'NO_OBSERVE_COMMAND', detail: 'fleet.json lane has no observe.argv for this platform.' };

    const proxy = await startProxy();
    const proxyUrl = `http://127.0.0.1:${proxy.port}`;
    const strace = (useStrace ?? platform === 'linux') && platform === 'linux' && existsSync('/usr/bin/strace');
    const straceOut = path.join(work, 'strace.txt');
    const argv = strace
      ? ['strace', '-f', '-qq', '-yy', '-xx', '-s', '2048', '-e', 'trace=connect,write,writev,sendto,sendmsg,sendmmsg', '-o', straceOut, ...cmd.argv]
      : cmd.argv;
    const env = {
      ...process.env, ...cmd.env,
      HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl,
      NODE_USE_ENV_PROXY: '1', NO_PROXY: '', no_proxy: '',
    };
    const win = platform === 'win32';
    const child = spawn(win ? argv.map(quoteWin).join(' ') : argv[0], win ? [] : argv.slice(1), {
      cwd, env, shell: win, detached: !win, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { if (stdout.length < 4000) stdout += d; });
    child.stderr.on('data', (d) => { if (stderr.length < 4000) stderr += d; });

    const mib = new ConnectionMib();
    let polling = true;
    const poll = (async () => {
      while (polling) {
        const [table, conns] = await Promise.all([processTable(platform), socketSnapshot(platform)]);
        const tree = descendants(table, child.pid);
        const treeConns = conns.filter((c) => c.pid != null && tree.has(c.pid));
        mib.ingest(treeConns, { now: new Date().toISOString(), markMissingClosed: true });
        await new Promise((r) => setTimeout(r, pollMs));
      }
    })();

    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; killTree(child, platform); }, timeoutMs);
    const exitCode = await new Promise((resolve) => {
      child.on('error', (e) => { stderr += String(e?.message ?? e); resolve(null); });
      child.on('exit', (code) => resolve(code));
    });
    clearTimeout(timer);
    // Reap helpers the CLI left behind in its process group (no-op when none remain).
    killTree(child, platform);
    polling = false;
    await poll;
    await proxy.close();

    const traced = strace && existsSync(straceOut) ? parseStrace(readFileSync(straceOut, 'utf8')) : null;
    return summarize({
      lane,
      cmd,
      platform,
      startedAt,
      exitCode,
      timedOut,
      stdout,
      stderr,
      tunnels: proxy.tunnels,
      sockets: mib.remoteEndpoints({ includeLoopback: true }),
      mib: mib.snapshot(),
      traced,
    });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** Merge the layers into one evidence record. Pure, so the test can drive it. */
export function summarize({ lane, cmd, platform, startedAt, exitCode, timedOut, stdout = '', stderr = '', tunnels = [], sockets = [], mib = null, traced = null }) {
  const hosts = new Map();
  const touch = (host, port, via, extra = {}) => {
    if (!host || isLoopback(host)) return;
    const key = `${host}:${port}`;
    const h = hosts.get(key) ?? { host, port, via: [], ips: [], up: 0, down: 0 };
    if (!h.via.includes(via)) h.via.push(via);
    const normIp = extra.ip ? (parseAddress(extra.ip)?.normalized ?? extra.ip) : null;
    if (normIp && !h.ips.includes(normIp)) h.ips.push(normIp);
    h.up += extra.up ?? 0;
    h.down += extra.down ?? 0;
    hosts.set(key, h);
  };
  for (const t of tunnels) touch(t.sni ?? t.host, t.port, t.scheme === 'connect' ? 'proxy-connect' : 'proxy-http', t);
  // SNI on a loopback leg is the CLI talking TLS through our proxy: already named above.
  for (const s of traced?.sni ?? []) if (!isLoopback(s.ip)) touch(s.host, s.port, 'tls-sni', { ip: s.ip });
  // A CLI that only reaches loopback ports may hand its traffic to a local proxy or
  // gateway outside its process tree - say so instead of reporting nothing.
  const loopbackOnly = [...new Set([...(traced?.connects ?? []), ...sockets].filter((c) => isLoopbackAddress(c.ip) && c.port !== 53).map((c) => c.port))];

  const named = new Set([...hosts.values()].flatMap((h) => h.ips));
  const unnamed = new Map();
  for (const c of [...sockets, ...(traced?.connects ?? [])]) {
    const addr = parseAddress(c.ip);
    const normIp = addr?.normalized ?? c.ip;
    if (isLoopback(normIp) || c.port === 53 || named.has(normIp)) continue;
    const proto = c.protocol ?? 'tcp';
    const key = `${proto}:${normIp}:${c.port}`;
    if (!unnamed.has(key)) {
      const entry = {
        ip: normIp,
        port: c.port,
        via: c.pid != null ? 'socket-table' : 'strace-connect',
      };
      if (c.protocol) entry.protocol = c.protocol;
      if (c.family ?? addr?.family) entry.family = c.family ?? addr.family;
      if (c.states?.length) entry.states = c.states;
      unnamed.set(key, entry);
    }
  }
  const hostList = [...hosts.values()].sort((a, b) => b.down + b.up - (a.down + a.up));
  const mibCount = (mib?.summary?.tcpConnections ?? 0) + (mib?.summary?.udpEndpoints ?? 0);
  const layers = { proxy: tunnels.length > 0, sockets: sockets.length > 0 || mibCount > 0, strace: traced ? true : null };
  const result = {
    lane: lane.lane,
    cli: lane.cli,
    platform,
    command: cmd.argv.join(' '),
    startedAt,
    exitCode,
    timedOut,
    honoredProxy: tunnels.length > 0,
    layers,
    hosts: hostList,
    unnamedConnections: [...unnamed.values()],
    dnsQuestions: [...new Set((traced?.dns ?? []).map((d) => d.name))],
    loopbackPorts: loopbackOnly,
    verdict: hostList.length ? 'OBSERVED' : unnamed.size ? 'OBSERVED_IP_ONLY' : loopbackOnly.length ? 'LOCAL_GATEWAY' : 'NOT_OBSERVED',
    plane: 'CONTROL',
    note: 'Observed hosts are where the CLI connects (control plane, ending at the TLS edge). They are not the inference origin.',
    output: { stdout: stdout.slice(0, 400), stderr: stderr.slice(0, 400) },
  };
  if (mib) result.connectionMib = mib;
  return result;
}
