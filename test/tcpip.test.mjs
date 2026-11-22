// RFC 1792 dual-stack TCP/UDP Connection MIB and address primitive tests (100% offline).
import assert from 'node:assert/strict';
import {
  ConnectionMib,
  TCP_STATE,
  cidrContains,
  cidrContains6,
  compressIpv6,
  expandIpv6Hex,
  ipCidrContains,
  ipv6ToBigInt,
  isActiveTcpState,
  isListenerTcpState,
  normalizeTcpState,
  parseAddress,
  parseEndpoint,
  parseLsof,
  parseNetstat,
  parseSs,
} from '../src/tcpip.mjs';

let pass = 0;
let fail = 0;
const t = async (name, fn) => {
  try { await fn(); pass++; console.log(`ok    ${name}`); } catch (e) { fail++; console.log(`FAIL  ${name} :: ${e.message}`); }
};

await t('IPv6 parsing, expansion, compression, and IPv4-mapped unwrapping', () => {
  assert.equal(expandIpv6Hex('2607:6bc0::10'), '26076bc0000000000000000000000010');
  assert.equal(compressIpv6(ipv6ToBigInt('2607:6bc0:0000:0000:0000:0000:0000:0010')), '2607:6bc0::10');
  assert.equal(parseAddress('[fe80::1]%eno1').normalized, 'fe80::1');
  assert.equal(parseAddress('[fe80::1]%eno1').zone, 'eno1');
  const mapped = parseAddress('::ffff:104.18.3.115');
  assert.equal(mapped.family, 'ipv4');
  assert.equal(mapped.normalized, '104.18.3.115');
  assert.equal(mapped.mappedFromIpv6, true);
  assert.equal(parseAddress('::ffff:127.0.0.1').isLoopback, true);
  assert.equal(parseAddress('::1').isLoopback, true);
  assert.equal(parseAddress('::').isUnspecified, true);
  assert.equal(parseAddress('0.0.0.0').isUnspecified, true);
});

await t('RFC 1792 IpxAddress parsing and unspecified wildcard', () => {
  const a = parseAddress('00001a2b:00aa00bbccdd');
  assert.equal(a.family, 'ipx');
  assert.equal(a.network, '00001a2b');
  assert.equal(a.node, '00aa00bbccdd');
  assert.equal(a.isUnspecified, false);
  const unspec = parseAddress('00000000:000000000000');
  assert.equal(unspec.family, 'ipx');
  assert.equal(unspec.isUnspecified, true);
});

await t('Dual-stack IPv4 + IPv6 CIDR containment', () => {
  assert.equal(cidrContains('104.18.0.0/16', '104.18.3.115'), true);
  assert.equal(cidrContains6('2606:4700::/32', '2606:4700:4408::ac40:9bd1'), true);
  assert.equal(cidrContains6('2606:4700::/32', '2607:6bc0::10'), false);
  assert.equal(ipCidrContains('2600:1900:8000::/44', '2600:1900:8000::1'), true);
  assert.equal(ipCidrContains('2600:1900:8000::/44', '104.18.3.115'), false);
});

await t('RFC 1792 / RFC 793 TCP state normalization across ss, lsof, and netstat', () => {
  assert.deepEqual(normalizeTcpState('ESTAB'), { name: 'established', code: TCP_STATE.established });
  assert.deepEqual(normalizeTcpState('SYN-SENT'), { name: 'synSent', code: TCP_STATE.synSent });
  assert.deepEqual(normalizeTcpState('SYN_RCVD'), { name: 'synReceived', code: TCP_STATE.synReceived });
  assert.deepEqual(normalizeTcpState('FIN-WAIT-1'), { name: 'finWait1', code: TCP_STATE.finWait1 });
  assert.deepEqual(normalizeTcpState('TIME_WAIT'), { name: 'timeWait', code: TCP_STATE.timeWait });
  assert.deepEqual(normalizeTcpState('LISTENING'), { name: 'listen', code: TCP_STATE.listen });
  assert.equal(isActiveTcpState(TCP_STATE.synSent), true);
  assert.equal(isActiveTcpState(TCP_STATE.timeWait), true);
  assert.equal(isActiveTcpState(TCP_STATE.listen), false);
  assert.equal(isListenerTcpState(TCP_STATE.listen), true);
  assert.equal(isListenerTcpState(TCP_STATE.closed), true);
  assert.equal(isListenerTcpState(TCP_STATE.established), false);
});

await t('Endpoint parser handles zones, brackets, wildcards, and IPv4-mapped IPv6', () => {
  assert.deepEqual(parseEndpoint('[fe80::3a2c:4aff:fe6e:d88]%eno1:546').port, 546);
  assert.equal(parseEndpoint('127.0.0.53%lo:53').normalized, '127.0.0.53');
  assert.equal(parseEndpoint('[::]:*').isUnspecified, true);
  assert.equal(parseEndpoint('[::]:*').wildcardPort, true);
  assert.equal(parseEndpoint('[::ffff:1.2.3.4]:443').normalized, '1.2.3.4');
});

await t('ss -tnupHa parser: TCP all states + UDP + wildcard listeners', () => {
  const sample = [
    'udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* users:(("wg",pid=50,fd=4))',
    'udp ESTAB  0 0 10.0.0.5:51000 [2606:4700::6812:373]:443 users:(("cli",pid=100,fd=9))',
    'tcp LISTEN 0 512 0.0.0.0:8080 0.0.0.0:* users:(("node",pid=100,fd=7))',
    'tcp LISTEN 0 512 127.0.0.1:34101 0.0.0.0:* users:(("hermes",pid=101,fd=8))',
    'tcp SYN-SENT 0 1 10.0.0.5:40001 104.18.3.115:443 users:(("cli",pid=100,fd=10))',
    'tcp TIME-WAIT 0 0 [2001:db8::1]:40002 [2607:6bc0::10]:443 users:(("cli",pid=100,fd=11))',
  ].join('\n');
  const rows = parseSs(sample);
  assert.equal(rows.length, 6);
  assert.equal(rows[0].protocol, 'udp');
  assert.equal(rows[0].localUnspecified, true);
  assert.equal(rows[1].protocol, 'udp');
  assert.equal(rows[1].ip, '2606:4700::6812:373');
  assert.equal(rows[4].state, 'synSent');
  assert.equal(rows[5].state, 'timeWait');
  assert.equal(rows[5].family, 'ipv6');
});

await t('lsof -F pcfnPT and netstat -ano parsers capture TCP states, UDP, and listeners', () => {
  const lsof = parseLsof([
    'p42', 'ccurl',
    'f5', 'PTCP', 'n10.0.0.5:50000->2607:6bc0::10:443', 'TST=SYN_SENT',
    'f6', 'PTCP', 'n*:8080', 'TST=LISTEN',
    'f7', 'PUDP', 'n*:5353',
    'f8', 'PUDP', 'n10.0.0.5:51000->104.18.3.115:443',
  ].join('\n'));
  assert.equal(lsof.length, 4);
  assert.equal(lsof[0].state, 'synSent');
  assert.equal(lsof[0].ip, '2607:6bc0::10');
  assert.equal(lsof[1].localUnspecified, true);
  assert.equal(lsof[2].protocol, 'udp');
  assert.equal(lsof[3].ip, '104.18.3.115');

  const ns = parseNetstat([
    '  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       900',
    '  TCP    10.0.0.5:51234         104.18.3.115:443       FIN_WAIT_2      1234',
    '  TCP    [2001:db8::1]:51235    [2607:6bc0::10]:443    ESTABLISHED     1234',
    '  UDP    0.0.0.0:5353           *:*                                    700',
    '  UDP    [::]:5353              *:*                                    700',
  ].join('\r\n'));
  assert.equal(ns.length, 5);
  assert.equal(ns[0].state, 'listen');
  assert.equal(ns[1].state, 'finWait2');
  assert.equal(ns[2].family, 'ipv6');
  assert.equal(ns[3].protocol, 'udp');
  assert.equal(ns[3].localUnspecified, true);
});

await t('RFC 1792 ConnectionMib separates 4 tables and tracks transient TCP lifecycles', () => {
  const mib = new ConnectionMib();
  // Tick 1: SYN-SENT + wildcard TCP listener + loopback listener + wildcard UDP + QUIC UDP
  mib.ingest(parseSs([
    'tcp SYN-SENT 0 1 10.0.0.5:40001 104.18.3.115:443 users:(("cli",pid=100,fd=10))',
    'tcp LISTEN 0 512 0.0.0.0:8080 0.0.0.0:* users:(("cli",pid=100,fd=7))',
    'tcp LISTEN 0 512 [::]:8080 [::]:* users:(("cli",pid=100,fd=8))',
    'tcp LISTEN 0 512 127.0.0.1:34101 0.0.0.0:* users:(("cli",pid=100,fd=9))',
    'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("cli",pid=100,fd=11))',
    'udp ESTAB  0 0 [2001:db8::1]:52000 [2606:4700::6812:373]:443 users:(("cli",pid=100,fd=12))',
  ].join('\n')), { now: '2026-11-22T00:00:01Z', markMissingClosed: true });

  // Tick 2: TCP transitions SYN-SENT -> ESTABLISHED
  mib.ingest(parseSs(
    'tcp ESTAB 0 0 10.0.0.5:40001 104.18.3.115:443 users:(("cli",pid=100,fd=10))',
  ), { now: '2026-11-22T00:00:02Z', markMissingClosed: true });

  // Tick 3: TCP disappears -> transient transition to closed(1)
  mib.ingest([], { now: '2026-11-22T00:00:03Z', markMissingClosed: true });

  const snap = mib.snapshot();
  assert.equal(snap.tcpConnTable.length, 1);
  assert.deepEqual(snap.tcpConnTable[0].states, ['synSent', 'established', 'closed']);
  assert.equal(snap.tcpConnTable[0].stateCode, TCP_STATE.closed);
  assert.equal(snap.tcpConnTable[0].closedAt, '2026-11-22T00:00:03Z');

  // Wildcard TCP listener on port 8080 collapsed by localPort (RFC 1792 tcpUnspecConnTable), dual-stack tracked
  assert.equal(snap.tcpUnspecConnTable.length, 1);
  assert.equal(snap.tcpUnspecConnTable[0].localPort, 8080);
  assert.deepEqual(snap.tcpUnspecConnTable[0].families.sort(), ['ipv4', 'ipv6']);

  // Bound loopback listener kept separate from unspecified listeners and active remote connections
  assert.equal(snap.tcpListeners.length, 1);
  assert.equal(snap.tcpListeners[0].localAddress, '127.0.0.1');

  // Wildcard UDP listener in udpUnspecTable, connected QUIC UDP/443 in udpTable
  assert.equal(snap.udpUnspecTable.length, 1);
  assert.equal(snap.udpUnspecTable[0].localPort, 5353);
  assert.equal(snap.udpTable.length, 1);
  assert.equal(snap.udpTable[0].remAddress, '2606:4700::6812:373');

  const remotes = mib.remoteEndpoints();
  assert.equal(remotes.length, 2);
  assert.deepEqual(remotes.map((r) => `${r.protocol}:${r.ip}:${r.port}`).sort(), [
    'tcp:104.18.3.115:443',
    'udp:2606:4700::6812:373:443',
  ]);
});

console.log(`\ntcpip: ${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
