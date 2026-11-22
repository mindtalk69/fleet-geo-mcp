// RFC 8805 geofeed, RFC 9293 edge timing/headers, and two-layer mapPins tests (100% offline).
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  extractGeofeedUrl,
  extractRdapScopes,
  isPrefixWithinScope,
  isSafeGeofeedUrl,
  lookupGeofeed,
  parseCacheTtlMs,
  parseGeofeedCsv,
} from '../src/geofeed.mjs';
import { coordsFor } from '../src/geo.mjs';
import { extractEdgePop, probeEdgeHeaders } from '../src/sources.mjs';
import { assemble } from '../src/classify.mjs';

let pass = 0;
let fail = 0;
const t = async (name, fn) => {
  try { await fn(); pass++; console.log(`ok    ${name}`); } catch (e) { fail++; console.log(`FAIL  ${name} :: ${e.message}`); }
};

await t('RFC 8805 §3.1: only public HTTPS geofeed URLs accepted', () => {
  assert.equal(isSafeGeofeedUrl('https://api.cloudflare.com/local-ip-ranges.csv'), true);
  assert.equal(isSafeGeofeedUrl('http://example.com/geofeed.csv'), false);
  assert.equal(isSafeGeofeedUrl('https://127.0.0.1/geofeed.csv'), false);
  assert.equal(isSafeGeofeedUrl('https://169.254.169.254/latest'), false);
  assert.equal(isSafeGeofeedUrl('https://localhost/geofeed.csv'), false);
});

await t('RFC 9092/9632 RDAP geofeed discovery (geofeedv1, links, remarks)', () => {
  assert.equal(extractGeofeedUrl({ geofeedv1_geofeed: 'https://net.example/feed.csv' }), 'https://net.example/feed.csv');
  assert.equal(
    extractGeofeedUrl({ links: [{ rel: 'geofeed', href: 'https://net.example/link.csv' }] }),
    'https://net.example/link.csv',
  );
  assert.equal(
    extractGeofeedUrl({ remarks: [{ description: ['Geofeed: https://api.cloudflare.com/local-ip-ranges.csv'] }] }),
    'https://api.cloudflare.com/local-ip-ranges.csv',
  );
  assert.equal(
    extractGeofeedUrl({ remarks: [{ description: ['Geofeed: http://insecure.example/feed.csv'] }] }),
    null,
  );
});

await t('RFC 8805 §2.1 CSV parser: IPv4, IPv6, comments, UTF-8 city, §2.1.2 empty opt-out', () => {
  const csv = [
    '# Geofeed https://isp.example/geofeed.csv',
    '',
    '198.51.100.0/24,DE,DE-HE,Frankfurt am Main,60311 # inline comment',
    '198.51.100.128/25,SG,SG-01,Singapore,',
    '2001:db8:abcd::/48,JP,JP-13,Tokyo,',
    '198.51.100.0/28,,,,', // RFC 8805 §2.1.2 explicit no-geolocation opt-out
    'not-a-prefix,US,,New York,',
  ].join('\r\n');
  const parsed = parseGeofeedCsv(csv);
  assert.equal(parsed.selfUrl, 'https://isp.example/geofeed.csv');
  assert.equal(parsed.total, 4);
  assert.equal(parsed.invalidLines, 1);
  assert.equal(parsed.entriesV4[0].city, 'Frankfurt am Main');
  assert.equal(parsed.entriesV4[2].noGeolocation, true);
  assert.equal(parsed.entriesV6[0].country, 'JP');
});

await t('RFC 8805 §3.2 authority verification blocks out-of-scope prefixes', async () => {
  const fakeFeed = [
    '198.51.100.0/24,DE,DE-HE,Frankfurt,',
    '203.0.113.0/24,US,US-VA,Ashburn,', // outside authorizing RDAP block!
    '2001:db8:1::/48,NL,NL-ZH,Rotterdam,',
  ].join('\n');
  const mockFetch = async () => ({
    ok: true,
    headers: new Map([['cache-control', 'max-age=7200']]),
    text: async () => fakeFeed,
  });

  const scopes = extractRdapScopes({ cidrs: ['198.51.100.0/24', '2001:db8:1::/48'] });
  assert.equal(isPrefixWithinScope(parseGeofeedCsv('198.51.100.0/25,DE,,').entriesV4[0], scopes), true);
  assert.equal(isPrefixWithinScope(parseGeofeedCsv('203.0.113.0/24,US,,').entriesV4[0], scopes), false);

  const okHit = await lookupGeofeed('198.51.100.42', { feedUrl: 'https://auth-test.example/geo.csv', scopes, fetchImpl: mockFetch });
  assert.equal(okHit.matched, true);
  assert.equal(okHit.authorityVerified, true);
  assert.equal(okHit.city, 'Frankfurt');
  assert.equal(okHit.coords.place, 'Frankfurt');

  const spoofed = await lookupGeofeed('203.0.113.9', { feedUrl: 'https://auth-test.example/geo.csv', scopes, fetchImpl: mockFetch });
  assert.equal(spoofed.matched, false);
  assert.equal(spoofed.rejectedOutOfScope, 1);

  const v6Hit = await lookupGeofeed('2001:db8:1::5', { feedUrl: 'https://auth-test.example/geo.csv', scopes, fetchImpl: mockFetch });
  assert.equal(v6Hit.matched, true);
  assert.equal(v6Hit.city, 'Rotterdam');
  assert.ok(v6Hit.coords.lat > 51 && v6Hit.coords.lat < 53);
});

await t('RFC 8805 §3.4 HTTP Cache-Control / Expires clamping', () => {
  assert.equal(parseCacheTtlMs({ 'cache-control': 'max-age=60' }), 3600_000); // clamped to 1h min
  assert.equal(parseCacheTtlMs({ 'cache-control': 'max-age=99999999' }), 7 * 86400_000); // clamped to 7d max
  assert.equal(parseCacheTtlMs({ 'cache-control': 'public, max-age=7200' }), 7200_000);
});

await t('Edge PoP header extraction and IATA coordinates', () => {
  assert.equal(extractEdgePop({ 'cf-ray': '8a1b2c3d4e5f-SIN' }).iata, 'SIN');
  assert.equal(extractEdgePop({ 'x-amz-cf-pop': 'CGK50-P1' }).iata, 'CGK');
  assert.equal(extractEdgePop({ 'x-served-by': 'cache-fra-eddf8230031-FRA' }).iata, 'FRA');
  assert.equal(extractEdgePop({ 'x-vercel-id': 'sin1::abc' }).iata, 'SIN');
  assert.equal(extractEdgePop({ 'fly-region': 'nrt' }).iata, 'NRT');
  const sin = coordsFor({ iata: 'SIN' });
  assert.equal(sin.place, 'Singapore');
  assert.equal(sin.precision, 'pop');
});

await t('probeEdgeHeaders captures RFC 9293 TCP connect RTT vs TTFB, edgePin, and originHints', async () => {
  const srv = http.createServer((_req, res) => {
    setTimeout(() => {
      res.writeHead(200, {
        'cf-ray': 'abc123-SIN',
        'x-supabase-region': 'ap-southeast-1',
        'server-timing': 'origin;dur=12',
      });
      res.end('ok');
    }, 15);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const r = await probeEdgeHeaders(`http://127.0.0.1:${srv.address().port}/`);
  assert.equal(r.edge.vendor, 'Cloudflare');
  assert.equal(r.edge.pop, 'SIN');
  assert.equal(r.edgePin.plane, 'EDGE');
  assert.equal(r.edgePin.iata, 'SIN');
  assert.equal(r.originHints['x-supabase-region'], 'ap-southeast-1');
  assert.ok(typeof r.timing.edgeTcpRttMs === 'number' && r.timing.edgeTcpRttMs >= 0);
  assert.ok(typeof r.timing.httpRttMs === 'number' && r.timing.httpRttMs >= 10);
  assert.ok(typeof r.timing.backendDeltaMs === 'number');
  await new Promise((r) => srv.close(r));
});

await t('Two-layer mapPins: OPEN edge stays null on origin; verified RFC 8805 unicast lifts to ANCHORED', () => {
  // Edge-only IP with local geofeed -> EDGE pin only, origin strictly null (OPEN)
  const edgeCard = assemble({
    subject: { host: 'api.example.com' },
    ipFacts: [{
      ip: '104.22.1.1',
      asn: { asn: 13335, org: 'CLOUDFLARENET', country: 'US' },
      geofeed: {
        matched: true,
        prefix: '104.22.1.0/24',
        country: 'US',
        region: 'US-GA',
        city: 'Atlanta',
        noGeolocation: false,
        authorityVerified: true,
        feedUrl: 'https://api.cloudflare.com/local-ip-ranges.csv',
        coords: coordsFor({ city: 'Atlanta', country: 'US' }),
      },
    }],
  });
  assert.equal(edgeCard.confidence, 'OPEN');
  assert.equal(edgeCard.mapPins.origin, null);
  assert.equal(edgeCard.mapPins.edge.plane, 'EDGE');
  assert.equal(edgeCard.mapPins.edge.place, 'Atlanta');

  // Unicast non-edge IP with RDAP-verified RFC 8805 geofeed -> ANCHORED originPin
  const originCard = assemble({
    subject: { host: 'direct.example.com' },
    ipFacts: [{
      ip: '198.51.100.42',
      asn: { asn: 24940, org: 'HETZNER-AS', country: 'DE' },
      geofeed: {
        matched: true,
        prefix: '198.51.100.0/24',
        country: 'DE',
        region: 'DE-SN',
        city: 'Falkenstein',
        noGeolocation: false,
        authorityVerified: true,
        feedUrl: 'https://hetzner.example/geofeed.csv',
        coords: coordsFor({ city: 'Falkenstein', country: 'DE' }),
      },
    }],
  });
  assert.equal(originCard.confidence, 'ANCHORED');
  assert.equal(originCard.location.precision, 'city');
  assert.equal(originCard.mapPins.origin.plane, 'ORIGIN');
  assert.equal(originCard.mapPins.origin.place, 'Falkenstein');
  assert.equal(originCard.mapPins.edge, null);
});

console.log(`\ngeofeed: ${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
