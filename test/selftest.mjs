// Self-test. Offline assertions are strict (they gate the exit code); network checks
// are tolerant, because a flaky upstream must not look like a broken tool.
import { cidrContains, cidrContains6, coordsFor, findRegionToken, fingerprintHost, haversineKm, ipv4ToInt, ipv6ToBigInt, jurisdictionFromHostname, regionFromHostname, rttFloorMs, rttViolates } from '../src/geo.mjs';
import { analyzeLatency, assemble, downgrade } from '../src/classify.mjs';
import { isEntitled, loadCatalog, matchProvider, recordFact } from '../src/catalog.mjs';
import { asnForIp, cloudRangeFor, runMeasurement } from '../src/sources.mjs';
import { resolveHost } from '../src/doh.mjs';
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

let pass = 0;
let fail = 0;
let warn = 0;

const t = async (name, fn) => {
  try {
    await fn();
    pass++;
    console.log(`ok    ${name}`);
  } catch (e) {
    fail++;
    console.log(`FAIL  ${name} :: ${e.message}`);
  }
};
const soft = async (name, fn) => {
  try {
    await fn();
    pass++;
    console.log(`ok    ${name}`);
  } catch (e) {
    warn++;
    console.log(`warn  ${name} :: ${e.message}`);
  }
};
const eq = (a, b, msg = '') => {
  if (a !== b) throw new Error(`${msg} expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
};
const ok = (v, msg) => {
  if (!v) throw new Error(msg ?? 'expected truthy');
};

console.log('--- offline: primitives ---');
await t('ipv4ToInt', () => eq(ipv4ToInt('1.2.3.4'), 16909060));
await t('cidrContains in', () => ok(cidrContains('1.1.1.0/24', '1.1.1.1')));
await t('cidrContains out', () => ok(!cidrContains('1.1.1.0/24', '1.1.2.1')));
await t('ipv6ToBigInt + cidrContains6', () => {
  ok(ipv6ToBigInt('2607:6bc0::10') !== null);
  ok(cidrContains6('2607:6bc0::/48', '2607:6bc0::10'));
  ok(!cidrContains6('2607:6bc0::/48', '2606:4700::1'));
});
await t('haversine HEL->IAD ~7000km', () => {
  const d = haversineKm({ lat: 60.17, lon: 24.94 }, { lat: 38.95, lon: -77.45 });
  ok(Math.abs(d - 7000) < 700, `got ${d}`);
});
await t('rtt floor 1000km = 10ms', () => eq(rttFloorMs(1000), 10));
await t('rtt violation Helsinki->Ashburn @1.4ms', () => ok(rttViolates(1.4, 7000)));
await t('rtt plausible @120ms', () => ok(!rttViolates(120, 7000)));
await t('region from bedrock hostname', () => eq(regionFromHostname('bedrock-runtime.us-east-2.amazonaws.com'), 'us-east-2'));
await t('region from vertex hostname', () => eq(regionFromHostname('europe-west4-aiplatform.googleapis.com'), 'europe-west4'));
await t('jurisdiction from regional gateway hostnames (OpenRouter US/EU, OpenAI regional)', () => {
  eq(jurisdictionFromHostname('us.openrouter.ai')?.country, 'US');
  eq(jurisdictionFromHostname('eu.openrouter.ai')?.country, 'EU');
  eq(jurisdictionFromHostname('eu.api.openai.com')?.country, 'EU');
  eq(jurisdictionFromHostname('jp.api.openai.com')?.country, 'JP');
  eq(jurisdictionFromHostname('openrouter.ai'), null);
});
await t('us.openrouter.ai anchors to US without inheriting DeepSeek CN residency', () => {
  const card = assemble({
    subject: { host: 'us.openrouter.ai', baseUrl: 'https://us.openrouter.ai/api/v1', model: 'deepseek-v4-pro', publisher: 'DeepSeek' },
    ipFacts: [{ ip: '104.18.3.115', asn: { asn: 13335, org: 'CLOUDFLARENET', country: 'US' } }],
    catalogFacts: null,
  });
  eq(card.confidence, 'ANCHORED');
  eq(card.location.country, 'US');
  eq(card.subject.publisher, 'DeepSeek');
  eq(card.mapPins.origin.country, 'US');
});
await t('cloudfront fingerprint is edge', () => eq(fingerprintHost('d3bbv8sr76az5s.cloudfront.net')?.plane, 'edge'));
await t('coordsFor region', () => ok(coordsFor({ region: 'ap-southeast-1' })?.place === 'Singapore'));

console.log('--- offline: catalog ---');
const catalog = loadCatalog();
await t('match deepseek', () => eq(matchProvider(catalog, { model: 'deepseek-flash-4.1-107' })?.key, 'deepseek'));
await t('match claude', () => eq(matchProvider(catalog, { model: 'claude-opus-5' })?.key, 'anthropic'));
await t('match gpt', () => eq(matchProvider(catalog, { model: 'gpt-6.1 sol' })?.key, 'openai'));
await t('match nemotron', () => eq(matchProvider(catalog, { model: 'nemotron-ultra-550' })?.key, 'nvidia'));
await t('match grok', () => eq(matchProvider(catalog, { model: 'grok 4.7' })?.key, 'xai'));
await t('match gemini', () => eq(matchProvider(catalog, { model: 'gemini-3.8-flash' })?.key, 'google'));
await t('match minimax', () => eq(matchProvider(catalog, { model: 'minimax-3.1' })?.key, 'minimax'));
await t('unresolved stays unresolved', () => eq(matchProvider(catalog, { model: 'muse wonder' })?.key, 'unresolved'));
await t('match by lane cli', () => eq(matchProvider(catalog, { lane: 'dsh' })?.key, 'deepseek'));
await t('entitled host allowed', () => ok(isEntitled('api.openai.com').allowed));
await t('stranger host refused', () => ok(!isEntitled('evil.example.com').allowed));

console.log('--- offline: fleet definition ---');
const fleet = JSON.parse(readFileSync(new URL('../fleet.json', import.meta.url), 'utf8'));
await t('fleet.json has all 10 lanes', () => eq(fleet.lanes.length, 10));
await t('every lane maps to a catalog provider', () => {
  const missing = fleet.lanes.filter((l) => !matchProvider(catalog, { lane: l.cli, model: l.model }));
  eq(missing.length, 0, `unmapped lanes: ${missing.map((l) => l.cli).join(',')}`);
});
await t('W7 is the dsh/deepseek lane', () => {
  const w7 = fleet.lanes.find((l) => l.lane === 'W7');
  eq(w7.cli, 'dsh');
  eq(matchProvider(catalog, { lane: w7.cli })?.key, 'deepseek');
});

console.log('--- offline: classification ---');
await t('downgrade', () => eq(downgrade('ANCHORED', 1), 'CORROBORATED'));
await t('cloud region anchor => ANCHORED', () => {
  const card = assemble({
    subject: { host: 'api.example.com', baseUrl: 'https://api.example.com' },
    ipFacts: [{ ip: '3.5.140.1', asn: { asn: 16509, org: 'AMAZON-02', country: 'US' }, cloud: { cloud: 'AWS', region: 'ap-northeast-2', prefix: '3.5.140.0/22', service: 'AMAZON', source: 'aws ip-ranges.json' } }],
  });
  eq(card.confidence, 'ANCHORED');
  eq(card.location.region, 'ap-northeast-2');
  eq(card.location.country, 'KR');
});
await t('cdn-only host => no origin claim', () => {
  const card = assemble({
    subject: { host: 'api.example.com' },
    ipFacts: [{ ip: '3.173.21.63', asn: { asn: 16509, org: 'AMAZON-02', country: 'US' }, cloud: { cloud: 'AWS', region: 'GLOBAL', prefix: '3.173.0.0/16', service: 'CLOUDFRONT', source: 'aws ip-ranges.json' } }],
  });
  ok(card.confidence === 'OPEN', `expected OPEN, got ${card.confidence}`);
  ok(card.planes.edge.operator !== null);
  ok(card.nextProbes.length > 0);
});
await t('latency falsifies a wrong origin', () => {
  const r = analyzeLatency({
    measurements: [{ city: 'Helsinki', country: 'FI', lat: 60.17, lon: 24.94, avgRttMs: 1.4 }],
    origin: { region: 'us-east-1', country: 'US' },
  });
  eq(r.verdict, 'FALSIFIED');
});
await t('anycast detected from flat RTT', () => {
  const r = analyzeLatency({
    measurements: [
      { city: 'Helsinki', country: 'FI', lat: 60.17, lon: 24.94, avgRttMs: 5 },
      { city: 'Singapore', country: 'SG', lat: 1.35, lon: 103.82, avgRttMs: 7 },
      { city: 'Ashburn', country: 'US', lat: 38.95, lon: -77.45, avgRttMs: 6 },
    ],
    origin: null,
  });
  ok(r.anycastLikely);
});

await t('region token anywhere in hostname (ELB)', () => eq(findRegionToken('internal-foo-123.ap-southeast-1.elb.amazonaws.com'), 'ap-southeast-1'));
await t('region token does not fire on plain CDN host', () => eq(findRegionToken('d3bbv8sr76az5s.cloudfront.net'), null));

console.log('--- offline: recording facts ---');
const tmpCat = path.join(mkdtempSync(path.join(tmpdir(), 'fleetgeo-')), 'catalog.json');
copyFileSync(path.join(path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Za-z]:)/, '$1'), '..', 'catalog.json'), tmpCat);

await t('record_fact rejects an unsourced fact', () => {
  const r = recordFact({ provider: 'deepseek', kind: 'residency', region: 'CN' }, { catalogPath: tmpCat });
  eq(r.ok, false);
  eq(r.error, 'INVALID_FACT');
});
await t('record_fact rejects a short quote', () => {
  const r = recordFact({ provider: 'deepseek', kind: 'residency', region: 'CN', source_url: 'https://example.com', quote: 'too short' }, { catalogPath: tmpCat });
  eq(r.ok, false);
});
await t('record_fact writes provenance', () => {
  const r = recordFact(
    { provider: 'deepseek', kind: 'residency', region: 'us-east-1', source_url: 'https://example.com/doc', quote: 'our inference runs in the us-east-1 region', verified_at: '2026-11-22' },
    { catalogPath: tmpCat },
  );
  ok(r.ok, JSON.stringify(r));
  const j = JSON.parse(readFileSync(tmpCat, 'utf8'));
  const p = j.providers.find((x) => x.key === 'deepseek');
  const fact = p.residency.find((x) => x.region === 'us-east-1');
  ok(fact, 'fact not written');
  eq(fact.source, 'https://example.com/doc');
  eq(fact.verifiedAt, '2026-11-22');
});
await t('verified fact lifts a card to ANCHORED', () => {
  const card = assemble({
    subject: { host: 'api.example.com' },
    ipFacts: [],
    catalogFacts: { publisher: 'X', residency: [{ region: 'us-east-1', country: 'US', default: true, source: 'https://example.com/doc', verifiedAt: '2026-11-22' }] },
  });
  eq(card.confidence, 'ANCHORED');
  eq(card.location.region, 'us-east-1');
});
await t('unverified fact does NOT lift a card', () => {
  const card = assemble({
    subject: { host: 'api.example.com' },
    ipFacts: [],
    catalogFacts: { publisher: 'X', residency: [{ region: 'CN', country: 'CN', default: true, source: 'unverified', verifiedAt: null }] },
  });
  ok(card.confidence === 'OPEN', `expected OPEN, got ${card.confidence}`);
  ok(card.warnings.length > 0);
});
await t('record_fact accepts a country-only statement at country precision', () => {
  const r = recordFact(
    { provider: 'minimax', kind: 'residency', country: 'cn', source_url: 'https://example.com/privacy', quote: 'we process your data in the People\'s Republic of China', verified_at: '2026-11-22' },
    { catalogPath: tmpCat },
  );
  ok(r.ok, JSON.stringify(r));
  eq(r.recorded.region, null);
  eq(r.recorded.country, 'CN');
  eq(r.recorded.precision, 'country');
  const bad = recordFact({ provider: 'minimax', kind: 'residency', country: 'China', source_url: 'https://example.com/p', quote: 'a quote that is long enough' }, { catalogPath: tmpCat });
  eq(bad.ok, false, 'country must be a 2-letter code');
});
await t('country-only documented fact anchors at country precision with its quote', () => {
  const card = assemble({
    subject: { host: 'api.example.com' },
    ipFacts: [],
    catalogFacts: { publisher: 'X', residency: [{ region: null, country: 'CN', precision: 'country', default: true, source: 'https://example.com/privacy', quote: 'we process your data in China', verifiedAt: '2026-11-22' }] },
  });
  eq(card.confidence, 'ANCHORED');
  eq(card.location.country, 'CN');
  eq(card.location.region, null);
  eq(card.location.precision, 'country');
  eq(card.mapPins.origin.precision, 'country');
  eq(card.mapPins.origin.basis, 'provider-documented');
  eq(card.mapPins.origin.quote, 'we process your data in China');
});
await t('a cited fact outranks an unverified seed marked default', () => {
  const card = assemble({
    subject: { host: 'api.example.com' },
    ipFacts: [],
    catalogFacts: { publisher: 'X', residency: [
      { region: 'CN', country: 'CN', default: true, source: 'provider documentation (to verify)', verifiedAt: null },
      { region: null, country: 'CN', precision: 'country', default: false, source: 'https://example.com/privacy', quote: 'processed in China', verifiedAt: '2026-11-22' },
    ] },
  });
  eq(card.confidence, 'ANCHORED');
  eq(card.mapPins.origin.basis, 'provider-documented');
});
await t('recording a cited fact makes it the default over an unverified seed', () => {
  // Use a synthetic unverified provider in tmpCat so verifying real providers in catalog.json never breaks this test.
  const raw = JSON.parse(readFileSync(tmpCat, 'utf8'));
  raw.providers.push({
    key: 'seedtest',
    publisher: 'SeedTest',
    match: ['^seedtest'],
    apiHosts: ['api.seedtest.example'],
    laneClis: [],
    residency: [{ region: 'US', country: 'US', default: true, source: 'unverified', verifiedAt: null }],
    facilityAnchors: [],
    status: 'hypothesis',
  });
  writeFileSync(tmpCat, `${JSON.stringify(raw, null, 2)}\n`, 'utf8');
  const r = recordFact(
    { provider: 'seedtest', kind: 'residency', country: 'US', source_url: 'https://example.com/seedtest', quote: 'data is processed in the United States', verified_at: '2026-11-22' },
    { catalogPath: tmpCat },
  );
  ok(r.ok, JSON.stringify(r));
  eq(r.recorded.default, true);
  const p = JSON.parse(readFileSync(tmpCat, 'utf8')).providers.find((x) => x.key === 'seedtest');
  ok(p.residency.filter((x) => x.default).length === 1, 'exactly one default');
});
await t('a bare API host matches its catalog provider', () => {
  eq(matchProvider(catalog, { host: 'api.deepseek.com' })?.key, 'deepseek');
  eq(matchProvider(catalog, { host: 'API.DEEPSEEK.COM' })?.matchedBy, 'host');
  eq(matchProvider(catalog, { host: 'unknown.example.com' }), null);
});

console.log('--- online: live sources (tolerant) ---');
let chain = null;
await soft('DoH resolve api.deepseek.com', async () => {
  chain = await resolveHost('api.deepseek.com');
  ok(chain.addresses.length > 0, 'no addresses');
  ok(chain.hops.length > 0, 'expected a CNAME hop');
});
await soft('ASN lookup', async () => {
  const ip = chain?.addresses?.[0]?.ip;
  ok(ip, 'no ip');
  const asn = await asnForIp(ip);
  ok(asn?.asn, 'no asn');
  console.log(`         ${ip} => AS${asn.asn} ${asn.org ?? ''} (${asn.country})`);
});
await soft('ASN lookup (IPv6 via origin6.asn.cymru.com)', async () => {
  const asn = await asnForIp('2607:6bc0::10');
  ok(asn?.asn === 399358, `expected AS399358, got ${asn?.asn}`);
  eq(asn.family, 'ipv6');
  console.log(`         2607:6bc0::10 => AS${asn.asn} ${asn.org ?? ''} (${asn.country})`);
});
await soft('published cloud region match (IPv4)', async () => {
  const ip = chain?.addresses?.[0]?.ip;
  ok(ip, 'no ip');
  const c = await cloudRangeFor(ip);
  ok(c, 'no cloud prefix match');
  console.log(`         ${ip} => ${c.cloud}/${c.region} (${c.service})`);
});
await soft('published cloud region match (IPv6)', async () => {
  const c = await cloudRangeFor('2600:1900:8000::1');
  ok(c?.cloud === 'GCP' && c.family === 'ipv6', `unexpected IPv6 cloud match: ${JSON.stringify(c)}`);
  console.log(`         2600:1900:8000::1 => ${c.cloud}/${c.region} (${c.service})`);
});
await soft('globalping probe', async () => {
  const m = await runMeasurement({ target: '1.1.1.1', limit: 3 });
  ok(m.results.length > 0, 'no results');
  console.log(`         ${m.results.length} probes, first ${m.results[0].city} ${m.results[0].avgRttMs}ms`);
});

console.log(`\n${pass} passed, ${fail} failed, ${warn} warned`);
if (fail > 0) process.exitCode = 1;
