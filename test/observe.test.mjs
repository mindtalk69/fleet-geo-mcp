// observe_endpoints checks. Offline and OS-independent: every network step uses loopback.
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  descendants, laneCommand, observeLane, parseClientHelloSni, parseDnsQuestion, parseLsof, parseNetstat,
  parseProcessTable, parseSs, parseStrace, startProxy, summarize,
} from '../src/observe.mjs';

let pass = 0;
let fail = 0;
const t = async (name, fn) => {
  try { await fn(); pass++; console.log(`ok    ${name}`); } catch (e) { fail++; console.log(`FAIL  ${name} :: ${e.message}`); }
};

/** A real ClientHello, captured from node:tls against a local socket. */
function captureClientHello(servername) {
  return new Promise((resolve) => {
    const srv = net.createServer((s) => s.once('data', (d) => { resolve(d); s.destroy(); srv.close(); }));
    srv.listen(0, '127.0.0.1', () => {
      const c = tls.connect({ host: '127.0.0.1', port: srv.address().port, servername, rejectUnauthorized: false });
      c.on('error', () => {});
    });
  });
}
const dnsQuery = (name, id = 0x1234) => {
  const labels = name.split('.').flatMap((l) => [l.length, ...Buffer.from(l)]);
  return Buffer.from([id >> 8, id & 255, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1]);
};
const hex = (buf) => [...buf].map((b) => `\\x${b.toString(16).padStart(2, '0')}`).join('');

const hello = await captureClientHello('api.example.com');

await t('SNI from a real ClientHello', async () => {
  assert.equal(parseClientHelloSni(hello), 'api.example.com');
  assert.equal(parseClientHelloSni(Buffer.from('GET / HTTP/1.1\r\n')), null);
  assert.equal(parseClientHelloSni(hello.subarray(0, 30)), null, 'truncated capture is not a hostname');
});

await t('DNS question name; responses ignored', async () => {
  assert.equal(parseDnsQuestion(dnsQuery('api.deepseek.com')), 'api.deepseek.com');
  const resp = dnsQuery('api.deepseek.com');
  resp[2] |= 0x80;
  assert.equal(parseDnsQuestion(resp), null);
});

await t('strace: connect, SNI and both sendmmsg DNS datagrams', async () => {
  const text = [
    `101 connect(7<TCP:[0]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.18.3.115")}, 16) = -1 EINPROGRESS`,
    `101 connect(8<TCP6:[0]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::6812:373", &sin6_addr), sin6_scope_id=0}, 28) = 0`,
    `101 write(7<TCP:[10.0.0.5:40000->104.18.3.115:443]>, "${hex(hello)}", ${hello.length}) = ${hello.length}`,
    `102 sendmmsg(5<UDP:[127.0.0.1:5000->127.0.0.53:53]>, [{msg_hdr={msg_iov=[{iov_base="${hex(dnsQuery('openrouter.ai', 1))}", iov_len=31}]}}, {msg_hdr={msg_iov=[{iov_base="${hex(dnsQuery('cdn.example.net', 2))}", iov_len=33}]}}], 2, MSG_NOSIGNAL) = 2`,
    `103 write(1</dev/pts/0>, "\\x4f\\x4b", 2) = 2`,
  ].join('\n');
  const r = parseStrace(text);
  assert.deepEqual(r.connects, [{ ip: '104.18.3.115', port: 443 }, { ip: '2606:4700::6812:373', port: 443 }]);
  assert.deepEqual(r.sni, [{ ip: '104.18.3.115', port: 443, host: 'api.example.com' }]);
  assert.deepEqual(r.dns.map((d) => d.name), ['openrouter.ai', 'cdn.example.net']);
});

await t('strace -xx: hex-escaped connect addresses are decoded (loopback recognised)', async () => {
  const r = parseStrace(`9 connect(3<TCP:[0]>, {sa_family=AF_INET, sin_port=htons(8787), sin_addr=inet_addr("${hex(Buffer.from('127.0.0.1'))}")}, 16) = 0`);
  assert.deepEqual(r.connects, [{ ip: '127.0.0.1', port: 8787 }]);
});

await t('proxy close() resolves while a tunnel is still open', async () => {
  const sink = net.createServer(() => {});
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const proxy = await startProxy();
  const sock = await new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: proxy.port, method: 'CONNECT', path: `127.0.0.1:${sink.address().port}` });
    req.on('connect', (_res, s) => resolve(s));
    req.end();
  });
  sock.on('error', () => {});
  const closed = await Promise.race([proxy.close().then(() => true), new Promise((r) => setTimeout(() => r(false), 3000))]);
  assert.equal(closed, true, 'close() hung on an open tunnel');
  sink.close();
});

await t('socket tables: ss (Linux), lsof (macOS), netstat (Windows)', async () => {
  assert.deepEqual(parseSs('ESTAB 0 0 10.0.0.5:40000 104.18.3.115:443 users:(("node",pid=4242,fd=21))\nESTAB 0 0 [::1]:1 [::ffff:1.2.3.4]:443 users:(("x",pid=7,fd=3))'),
    [{ ip: '104.18.3.115', port: 443, pid: 4242 }, { ip: '1.2.3.4', port: 443, pid: 7 }]);
  assert.deepEqual(parseLsof('p4242\nf21\nn10.0.0.5:40000->104.18.3.115:443\np99\nn[::1]:5->[2606:4700::1]:443'),
    [{ ip: '104.18.3.115', port: 443, pid: 4242 }, { ip: '2606:4700::1', port: 443, pid: 99 }]);
  assert.deepEqual(parseNetstat('  Proto  Local  Foreign  State  PID\r\n  TCP    10.0.0.5:51234    104.18.3.115:443    ESTABLISHED     1234\r\n  TCP    [::1]:5    [2606:4700::1]:443    ESTABLISHED     88\r\n  TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    900'),
    [{ ip: '104.18.3.115', port: 443, pid: 1234 }, { ip: '2606:4700::1', port: 443, pid: 88 }]);
});

await t('process tree from ps and Windows CSV', async () => {
  const ps = parseProcessTable('  1  0\n 10  1\n 11 10\n 12 11\n 20  1');
  assert.deepEqual([...descendants(ps, 10)].sort(), [10, 11, 12]);
  const win = parseProcessTable('"ProcessId","ParentProcessId"\r\n"4","0"\r\n"500","4"\r\n"600","500"');
  assert.deepEqual([...descendants(win, 500)].sort(), [500, 600]);
});

await t('lane command: prompt, fixture vars, platform override', async () => {
  const lane = { lane: 'X', observe: { argv: ['cli', '-p', '{prompt}'], argvByPlatform: { linux: ['script', '-qec', 'cli', '/dev/null'] }, env: { LOG: '{tmp}/g' } } };
  assert.deepEqual(laneCommand(lane, 'win32', { tmp: 'T' }).argv, ['cli', '-p', 'Reply with exactly: OK']);
  assert.deepEqual(laneCommand(lane, 'linux').argv, ['script', '-qec', 'cli', '/dev/null']);
  assert.equal(laneCommand(lane, 'darwin', { tmp: 'T' }).env.LOG, 'T/g');
  assert.equal(laneCommand({ lane: 'Y' }), null);
});

await t('proxy tunnels bytes untouched and records host, SNI and volume', async () => {
  const echo = net.createServer((s) => s.pipe(s));
  await new Promise((r) => echo.listen(0, '127.0.0.1', r));
  const proxy = await startProxy();
  const reply = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: proxy.port, method: 'CONNECT', path: `127.0.0.1:${echo.address().port}` });
    req.on('connect', (res, sock) => {
      assert.equal(res.statusCode, 200);
      sock.write(hello);
      let got = Buffer.alloc(0);
      sock.on('data', (d) => { got = Buffer.concat([got, d]); if (got.length >= hello.length) { sock.destroy(); resolve(got); } });
    });
    req.on('error', reject);
    req.end();
  });
  assert.ok(reply.equals(hello), 'bytes changed in transit');
  const [rec] = proxy.tunnels;
  assert.equal(rec.host, '127.0.0.1');
  assert.equal(rec.sni, 'api.example.com');
  assert.ok(rec.up >= hello.length && rec.down >= hello.length);
  await proxy.close();
  echo.close();
});

await t('summarize: SNI names an IP; unnamed IPs kept; loopback and DNS dropped', async () => {
  const s = summarize({
    lane: { lane: 'W9', cli: 'x' }, cmd: { argv: ['x'] }, platform: 'linux', exitCode: 0, timedOut: false,
    tunnels: [], sockets: [{ ip: '104.18.3.115', port: 443, pid: 5 }, { ip: '9.9.9.9', port: 443, pid: 5 }, { ip: '127.0.0.1', port: 8787, pid: 5 }],
    traced: { connects: [{ ip: '1.1.1.1', port: 53 }], sni: [{ ip: '104.18.3.115', port: 443, host: 'openrouter.ai' }], dns: [{ name: 'openrouter.ai' }] },
  });
  assert.equal(s.verdict, 'OBSERVED');
  assert.deepEqual(s.hosts.map((h) => [h.host, h.ips, h.via]), [['openrouter.ai', ['104.18.3.115'], ['tls-sni']]]);
  assert.deepEqual(s.unnamedConnections, [{ ip: '9.9.9.9', port: 443, via: 'socket-table' }]);
  assert.deepEqual(s.dnsQuestions, ['openrouter.ai']);
  assert.equal(s.plane, 'CONTROL');
});

await t('observeLane end to end: a child that honours HTTPS_PROXY is observed', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'observe-test-'));
  const script = path.join(dir, 'child.mjs');
  writeFileSync(script, [
    "import http from 'node:http';",
    'const u = new URL(process.env.HTTPS_PROXY);',
    "const req = http.request({ host: u.hostname, port: u.port, method: 'CONNECT', path: 'probe.invalid:443' });",
    "req.on('connect', (res, s) => { s.destroy(); });",
    "req.on('response', () => {}); req.on('error', () => {}); req.on('close', () => process.exit(0));",
    'req.end();',
    'setTimeout(() => process.exit(0), 3000);',
  ].join('\n'));
  const lane = { lane: 'Z', cli: 'node', observe: { argv: [process.execPath, script] } };
  const r = await observeLane(lane, { timeoutMs: 15_000, useStrace: false, pollMs: 100 });
  assert.equal(r.timedOut, false);
  assert.equal(r.honoredProxy, true);
  assert.equal(r.hosts[0]?.host, 'probe.invalid');
  assert.deepEqual(r.hosts[0].via, ['proxy-connect']);
});

console.log(`\nobserve: ${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
