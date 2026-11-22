// Encore-style Rust N-API native core tests (gracefully skips native-only assertions
// if the .node binary has not been built yet, unless REQUIRE_NATIVE=1).
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { getNative, nativeStatus } from '../src/native.mjs';
import { ConnectionMib, parseAddress as jsParseAddress } from '../src/tcpip.mjs';

let pass = 0;
let fail = 0;
let skipped = 0;
const t = async (name, fn) => {
  try { await fn(); pass++; console.log(`ok    ${name}`); } catch (e) { fail++; console.log(`FAIL  ${name} :: ${e.message}`); }
};

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

const native = getNative();
const status = nativeStatus();

await t('nativeStatus returns valid descriptor', () => {
  assert.ok(status.engine === 'rust-napi' || status.engine === 'js-fallback');
  assert.equal(status.loaded, Boolean(native));
});

if (!native) {
  if (process.env.REQUIRE_NATIVE === '1') {
    console.error('FAIL  REQUIRE_NATIVE=1 set, but Rust N-API addon is not loaded:', status.reason);
    process.exit(1);
  }
  skipped++;
  console.log(`skip  Rust N-API addon not built (${status.reason})`);
} else {
  await t('Rust N-API runtimeInfo reports capabilities', () => {
    const info = native.runtimeInfo();
    assert.equal(info.engine, 'rust-napi');
    assert.ok(info.capabilities.includes('kernel-sockets'));
    assert.ok(info.capabilities.includes('lpm-radix-trie'));
  });

  await t('Rust normalizeAddress matches JS parseAddress across IPv4, IPv6, mapped, and IPX', () => {
    const samples = [
      '104.18.3.115',
      '2607:6bc0:0000:0000::10',
      '::ffff:127.0.0.1',
      '[fe80::1]%eno1',
      '00001a2b:00aa00bbccdd',
      '00000000:000000000000',
      '0.0.0.0',
      '::',
    ];
    for (const s of samples) {
      const r = native.normalizeAddress(s);
      const j = jsParseAddress(s);
      assert.equal(r.family, j.family, `family mismatch for ${s}`);
      assert.equal(r.normalized, j.normalized, `normalized mismatch for ${s}`);
      assert.equal(r.isUnspecified, j.isUnspecified, `isUnspecified mismatch for ${s}`);
      assert.equal(r.isLoopback, j.isLoopback, `isLoopback mismatch for ${s}`);
    }
  });

  await t('Rust PrefixTable performs dual-stack IPv4 + IPv6 longest-prefix match', () => {
    const table = new native.PrefixTable();
    const added = table.insertBatch([
      { cidr: '3.0.0.0/8', cloud: 'AWS', region: 'GLOBAL', service: 'AMAZON', source: 'aws' },
      { cidr: '3.5.140.0/22', cloud: 'AWS', region: 'ap-northeast-2', service: 'EC2', source: 'aws' },
      { cidr: '2600:1900::/28', cloud: 'GCP', region: 'global', service: 'Google Cloud', source: 'gcp' },
      { cidr: '2600:1900:8000::/44', cloud: 'GCP', region: 'africa-south1', service: 'Google Cloud', source: 'gcp' },
    ]);
    assert.equal(added, 4);
    assert.equal(table.lookup('3.5.140.1').region, 'ap-northeast-2');
    assert.equal(table.lookup('3.1.1.1').region, 'GLOBAL');
    assert.equal(table.lookup('::ffff:3.5.140.1').region, 'ap-northeast-2');
    assert.equal(table.lookup('2600:1900:8000::1').region, 'africa-south1');
    assert.equal(table.lookup('2600:1900:0001::1').region, 'global');
    assert.equal(table.lookup('127.0.0.1'), null);
    const st = table.stats();
    assert.equal(st.ipv4Count, 2);
    assert.equal(st.ipv6Count, 2);
  });

  await t('Rust zero-copy SNI and DNS parsers match real packets', async () => {
    const hello = await captureClientHello('api.anthropic.com');
    assert.equal(native.parseClientHelloSni(hello), 'api.anthropic.com');
    assert.equal(native.parseClientHelloSni(Buffer.from('GET / HTTP/1.1\r\n')), null);
    assert.equal(native.parseDnsQuestion(dnsQuery('api.deepseek.com')), 'api.deepseek.com');
    const resp = dnsQuery('api.deepseek.com');
    resp[2] |= 0x80;
    assert.equal(native.parseDnsQuestion(resp), null);
  });

  await t('Rust kernel snapshotProcesses finds current Node process and parent', () => {
    const procs = native.snapshotProcesses();
    assert.ok(procs.length > 0, 'expected live processes');
    const me = procs.find((p) => p.pid === process.pid);
    assert.ok(me, `current pid ${process.pid} not found`);
    assert.equal(me.ppid, process.ppid);
  });

  await t('Rust kernel snapshotSockets observes a live loopback TCP server & client without subprocesses', async () => {
    const srv = net.createServer((s) => s.resume());
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const port = srv.address().port;
    const cli = net.connect(port, '127.0.0.1');
    await new Promise((r) => cli.once('connect', r));

    const socks = native.snapshotSockets();
    const mib = new ConnectionMib();
    mib.ingest(socks);
    const snap = mib.snapshot();

    const listener = snap.tcpListeners.find((l) => l.localAddress === '127.0.0.1' && l.localPort === port);
    const active = snap.tcpConnTable.find((c) => c.remAddress === '127.0.0.1' && c.remPort === port && c.state === 'established');
    assert.ok(listener, `expected listener on 127.0.0.1:${port}`);
    assert.ok(active, `expected established connection to 127.0.0.1:${port}`);
    assert.equal(active.pid, process.pid);

    cli.destroy();
    await new Promise((r) => srv.close(r));
  });
}

console.log(`\nnative (${status.engine}): ${pass} passed, ${fail} failed, ${skipped} skipped`);
if (fail) process.exitCode = 1;
