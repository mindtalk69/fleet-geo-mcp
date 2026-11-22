// Evidence assembly and confidence. This is the part that must never lie:
// the tool returns what was observed, which plane it belongs to, and how sure it is.
import { EDGE_ASNS, REGION_COUNTRY, coordsFor, fingerprintHost, haversineKm, regionFromHostname, round, rttFloorMs, rttViolates } from './geo.mjs';

const TIER_WEIGHT = { A: 4, B: 3, C: 2, D: 1 };
const ORDER = ['OPEN', 'INDICATED', 'CORROBORATED', 'ANCHORED'];

export function downgrade(state, steps = 1) {
  const i = ORDER.indexOf(state);
  return ORDER[Math.max(0, Math.min(ORDER.length - 1, i - steps))];
}

/**
 * Turn raw observations into a four-plane card.
 * Nothing here invents a location: every claim traces to an evidence row.
 */
export function assemble({ subject, chain, ipFacts = [], facilities = null, catalogFacts = null }) {
  const evidence = [];
  const contradictions = [];
  const warnings = [];

  const add = (tier, source, observed, claims = null) => {
    const e = { id: `E${evidence.length + 1}`, tier, source, observed, claims, at: new Date().toISOString() };
    evidence.push(e);
    return e;
  };

  /* ---- control plane -------------------------------------------------- */
  const control = {
    input: subject.input ?? null,
    baseUrl: subject.baseUrl ?? null,
    host: subject.host ?? null,
    publisher: subject.publisher ?? null,
    servingEntity: subject.servingEntity ?? null,
  };
  if (control.host) add('B', 'CLI config or operator input', `requests go to ${control.host}`, { host: control.host });

  /* ---- edge plane ----------------------------------------------------- */
  const fp = (control.host ? fingerprintHost(control.host) : null) ?? (chain?.finalHost ? fingerprintHost(chain.finalHost) : null);
  const edgeFacts = [];
  for (const f of ipFacts) {
    // A concrete published region is an origin anchor even when the ASN is a
    // hyperscaler's (AS16509 carries both CloudFront and EC2). Only a global /
    // CDN-scoped prefix, or an edge ASN with no concrete region, is an edge fact.
    const concreteRegion = Boolean(f.cloud?.region) && !/^global$/i.test(String(f.cloud.region));
    const edgeByCloud = Boolean(f.cloud) && (!concreteRegion || /cloudfront/i.test(String(f.cloud.service ?? '')));
    const edgeByAsn = Boolean(f.asn && EDGE_ASNS[f.asn.asn]) && !concreteRegion;
    if (edgeByCloud || edgeByAsn || fp?.plane === 'edge') edgeFacts.push(f);
  }

  const edge = {
    operator: fp?.operator ?? edgeFacts[0]?.asn?.org ?? null,
    pop: null,
    city: null,
    ip: edgeFacts[0]?.ip ?? null,
    asn: edgeFacts[0]?.asn?.asn ?? null,
    note: 'TLS termination point, near the caller. Never an inference origin.',
  };
  let edgePin = null;
  if (edgeFacts.length) {
    add(
      'B',
      edgeFacts[0].cloud ? edgeFacts[0].cloud.source : 'Team Cymru DNS',
      `${edgeFacts[0].ip} is ${edgeFacts[0].asn?.org ?? 'unknown'} (AS${edgeFacts[0].asn?.asn ?? '?'})` +
        (edgeFacts[0].cloud ? `; published prefix ${edgeFacts[0].cloud.prefix} => ${edgeFacts[0].cloud.region}/${edgeFacts[0].cloud.service}` : ''),
      { plane: 'edge', operator: edgeFacts[0].asn?.org ?? null },
    );
    const edgeGf = edgeFacts.find((f) => f.geofeed?.matched && !f.geofeed.noGeolocation)?.geofeed;
    if (edgeGf) {
      edge.city = edgeGf.city ?? null;
      add(
        'B',
        `RFC 8805 geofeed (${edgeGf.feedUrl})`,
        `edge IP falls in ${edgeGf.prefix} => ${[edgeGf.city, edgeGf.region, edgeGf.country].filter(Boolean).join(', ')} (edge plane only)`,
        { plane: 'edge', country: edgeGf.country ?? null },
      );
      if (edgeGf.coords) {
        edgePin = {
          lat: edgeGf.coords.lat,
          lon: edgeGf.coords.lon,
          place: edgeGf.city ?? edgeGf.coords.place ?? edgeGf.country,
          country: edgeGf.country ?? edgeGf.coords.country ?? null,
          plane: 'EDGE',
          precision: edgeGf.coords.precision ?? 'city',
          source: `RFC 8805 geofeed (${edgeGf.feedUrl})`,
        };
      }
    }
  }

  /* ---- origin plane --------------------------------------------------- */
  const originCandidates = ipFacts.filter((f) => !edgeFacts.includes(f));
  const origin = {
    country: null,
    region: null,
    city: null,
    facility: null,
    precision: 'unknown',
    cloud: null,
  };

  for (const f of originCandidates) {
    if (f.cloud?.region && f.cloud.region !== 'GLOBAL') {
      const cc = REGION_COUNTRY[String(f.cloud.region).toLowerCase()] ?? null;
      add(
        'A',
        f.cloud.source,
        `${f.ip} falls in ${f.cloud.prefix}, published as ${f.cloud.cloud} region ${f.cloud.region}`,
        { country: cc, region: f.cloud.region, plane: 'origin', anchor: 'cloud-published-region' },
      );
      if (!origin.region) {
        origin.region = f.cloud.region;
        origin.country = cc;
        origin.cloud = f.cloud.cloud;
        origin.precision = 'region';
      }
    } else if (f.geofeed?.matched && !f.geofeed.noGeolocation) {
      const gf = f.geofeed;
      const tier = gf.authorityVerified ? 'A' : 'B';
      const label = [gf.city, gf.region, gf.country].filter(Boolean).join(', ');
      add(
        tier,
        `RFC 8805 geofeed (${gf.feedUrl})`,
        `${f.ip} falls in ${gf.prefix}, self-published as ${label}${gf.authorityVerified ? ' (RDAP authority verified)' : ' (unverified authority)'}`,
        { country: gf.country ?? null, region: gf.region ?? null, city: gf.city ?? null, plane: 'origin', anchor: 'rfc8805-geofeed' },
      );
      if (!origin.region && !origin.city) {
        origin.country = gf.country ?? origin.country;
        origin.region = gf.region ?? origin.region;
        origin.city = gf.city ?? origin.city;
        origin.precision = gf.city ? 'city' : gf.region ? 'region' : gf.country ? 'country' : origin.precision;
      }
    } else if (f.asn) {
      add('B', 'Team Cymru DNS', `${f.ip} is originated by ${f.asn.org ?? 'unknown'} (AS${f.asn.asn}), country ${f.asn.country ?? '?'}`, {
        country: f.asn.country ?? null,
        plane: 'origin',
        anchor: 'asn-registration',
      });
      if (!origin.country && f.asn.country) {
        origin.country = f.asn.country;
        origin.precision = 'country';
      }
    }
  }

  // A region encoded in the operator's own hostname is a deliberate disclosure.
  const hostCandidates = [control.host, chain?.finalHost, ...(chain?.hops ?? []).map((h) => h.to)].filter(Boolean);
  for (const cand of hostCandidates) {
    const hr = regionFromHostname(cand);
    if (!hr) continue;
    add('A', 'hostname convention', `${cand} encodes region ${hr}`, {
      region: hr,
      country: REGION_COUNTRY[hr] ?? null,
      plane: 'origin',
      anchor: 'region-encoded-hostname',
    });
    origin.region = hr;
    origin.country = REGION_COUNTRY[hr] ?? origin.country;
    origin.precision = 'region';
    break;
  }

  if (facilities?.facilities?.length) {
    const nonEdge = !EDGE_ASNS[facilities.asn];
    const sample = facilities.facilities.slice(0, 5).map((f) => `${f.name} (${f.city}, ${f.country})`);
    add(
      'B',
      'PeeringDB',
      `${facilities.name} (AS${facilities.asn}) has ${facilities.facilityCount} facilities; e.g. ${sample.join('; ')}`,
      nonEdge ? { country: facilities.facilities[0].country, plane: 'origin', anchor: 'peeringdb-facility' } : null,
    );
    if (nonEdge && !origin.region) {
      origin.country = origin.country ?? facilities.facilities[0].country;
      origin.facility = facilities.facilities[0].name;
      origin.precision = 'facility';
    }
    if (!nonEdge) {
      warnings.push(
        `AS${facilities.asn} (${facilities.name}) is an anycast/CDN network: its ${facilities.facilityCount} facilities are PoPs, not inference sites.`,
      );
    }
  }

  /* ---- catalog (documentation) ---------------------------------------- */
  if (catalogFacts?.residency?.length) {
    const r = catalogFacts.residency.find((x) => x.default) ?? catalogFacts.residency[0];
    if (r.verifiedAt) {
      add('A', r.source ?? 'provider documentation', `documented residency: ${r.region}`, {
        country: r.country ?? null,
        region: r.region,
        plane: 'origin',
        anchor: 'provider-documented',
      });
      if (!origin.region) {
        origin.region = r.region;
        origin.country = r.country ?? origin.country;
        origin.precision = 'region';
      }
    } else {
      add('D', 'catalog hypothesis (UNVERIFIED)', `claimed residency: ${r.region} - not verified against a source`, null);
      warnings.push(`Catalog residency for ${catalogFacts.publisher ?? 'this provider'} is unverified; it is a lead, not evidence.`);
    }
  }

  if (catalogFacts?.facilityAnchors?.length) {
    for (const a of catalogFacts.facilityAnchors) {
      add(a.verifiedAt ? 'A' : 'D', a.source ?? 'catalog', `anchor: ${a.name} (${a.city}, ${a.country})`, a.verifiedAt ? { country: a.country, facility: a.name, plane: 'origin', anchor: 'documented-facility' } : null);
      if (a.verifiedAt && !origin.facility) {
        origin.facility = a.name;
        origin.country = origin.country ?? a.country;
        origin.precision = 'facility';
      }
    }
  }

  /* ---- confidence ------------------------------------------------------ */
  const votes = evidence.filter((e) => e.claims && e.claims.plane === 'origin' && (e.claims.country || e.claims.region));
  const anchors = votes.filter((v) => v.tier === 'A');
  const lead = leadCountry(votes, origin);

  let state = 'OPEN';
  if (anchors.length) state = 'ANCHORED';
  else if (agreeingSources(votes, lead) >= 2) state = 'CORROBORATED';
  else if (votes.length) state = 'INDICATED';

  if (contradictions.length) state = downgrade(state, contradictions.length);

  const why = [];
  if (state === 'OPEN') why.push('no origin-plane source produced a defensible country or region');
  if (anchors.length) why.push(`${anchors.length} tier-A anchor(s): ${anchors.map((a) => a.claims.anchor).join(', ')}`);
  if (!anchors.length && votes.length) why.push(`${votes.length} origin vote(s) from ${new Set(votes.map((v) => v.source)).size} source(s)`);
  if (contradictions.length) why.push(`downgraded by ${contradictions.length} contradiction(s)`);

  const nextProbes = suggestNext({ state, origin, edge: edgeFacts.length > 0, chain, control });

  const originCoords =
    state !== 'OPEN'
      ? coordsFor({ city: origin.city, region: origin.region, country: origin.country })
      : null;
  const originPin = originCoords
    ? {
        lat: originCoords.lat,
        lon: originCoords.lon,
        place: origin.facility ?? origin.city ?? originCoords.place ?? origin.region ?? origin.country,
        country: origin.country ?? originCoords.country ?? null,
        region: origin.region ?? null,
        plane: 'ORIGIN',
        precision: origin.precision,
        confidence: state,
        source: anchors[0]?.source ?? votes[0]?.source ?? null,
      }
    : null;

  return {
    subject: { ...subject, publisher: control.publisher, servingEntity: control.servingEntity },
    planes: {
      control,
      edge,
      origin,
      legal: {
        entity: catalogFacts?.legalEntity ?? null,
        residency: catalogFacts?.residency ?? null,
        note: 'Legal plane is documentary. It constrains the origin plane and is what a DPO accepts.',
      },
    },
    location: {
      country: origin.country ?? null,
      region: origin.region ?? null,
      city: origin.city ?? null,
      facility: origin.facility ?? null,
      precision: origin.precision,
      cloud: origin.cloud ?? null,
      coords: originCoords ? { lat: originCoords.lat, lon: originCoords.lon, place: originCoords.place ?? null } : null,
    },
    mapPins: {
      edge: edgePin,
      origin: originPin,
    },
    confidence: state,
    confidenceWhy: why.join('; '),
    contradictions,
    warnings,
    evidence,
    nextProbes,
    chain: chain ?? null,
  };
}

function leadCountry(votes, origin) {
  if (origin.country) return origin.country;
  const score = new Map();
  for (const v of votes) {
    if (!v.claims.country) continue;
    score.set(v.claims.country, (score.get(v.claims.country) ?? 0) + (TIER_WEIGHT[v.tier] ?? 1));
  }
  const sorted = [...score.entries()].sort((a, b) => b[1] - a[1]);
  return sorted[0]?.[0] ?? null;
}

function agreeingSources(votes, country) {
  if (!country) return 0;
  return new Set(votes.filter((v) => v.claims.country === country).map((v) => v.source)).size;
}

function suggestNext({ state, origin, edge, chain, control }) {
  const out = [];
  if (!control.host) out.push('Provide the base URL the CLI actually uses (read its --help/config/env); everything downstream depends on it.');
  if (edge && state === 'OPEN') {
    out.push('The hostname resolves to a CDN edge, so the origin is hidden. Find the serving entity from the aggregator/CLI response metadata (e.g. a provider field), then re-trace that entity\'s endpoint.');
  }
  if (state === 'INDICATED') out.push('Add a second independent source type (documentation, published prefix table, or a PeeringDB facility) to lift this out of INDICATED.');
  if (state === 'CORROBORATED' || state === 'INDICATED') out.push('Run probe_latency from >=3 continents: the RTT bound either confirms the claimed region or falsifies it.');
  if (state === 'ANCHORED' && !origin.facility) out.push('Region is anchored. A facility needs documentary evidence: provider subprocessor list, status page, or a published compute announcement.');
  if (origin.precision === 'country') out.push('Country only. A regional endpoint (e.g. <region>-aiplatform.googleapis.com, bedrock-runtime.<region>.amazonaws.com) would move this to region precision.');
  return [...new Set(out)];
}

/**
 * RTT bound: fiber at ~200,000 km/s means 1 ms of round trip buys ~100 km of path.
 * From a probe at Helsinki measuring 1.4 ms, the origin must lie within ~140 km.
 * Intersect a few of these rings and you get a region - and a violation kills a claim.
 */
export function analyzeLatency({ measurements = [], origin = null }) {
  const tested = origin ? coordsFor({ region: origin.region, country: origin.country }) : null;
  const rows = measurements.map((m) => {
    const probe = m.lat != null && m.lon != null ? { lat: m.lat, lon: m.lon } : null;
    const distanceKm = probe && tested ? haversineKm(probe, tested) : null;
    const floorMs = rttFloorMs(distanceKm);
    const violation = distanceKm !== null ? rttViolates(m.avgRttMs, distanceKm) : null;
    return {
      probe: [m.city, m.country].filter(Boolean).join(', ') || 'unknown',
      network: m.network,
      avgRttMs: round(m.avgRttMs, 2),
      resolvedAddress: m.resolvedAddress,
      impliedMaxDistanceKm: m.avgRttMs != null ? Math.round(m.avgRttMs * 100) : null,
      distanceToClaimedOriginKm: distanceKm === null ? null : Math.round(distanceKm),
      floorMs: floorMs === null ? null : round(floorMs, 1),
      violation,
    };
  });

  const contradictions = rows
    .filter((r) => r.violation)
    .map(
      (r) =>
        `${r.probe}: ${r.avgRttMs} ms cannot reach the claimed origin at ${r.distanceToClaimedOriginKm} km ` +
        `(physical floor ${r.violation.floorMs} ms). The claimed origin is wrong, or the endpoint is an anycast edge.`,
    );

  const rtts = rows.map((r) => r.avgRttMs).filter((v) => Number.isFinite(v));
  const spread = rtts.length > 1 ? Math.max(...rtts) - Math.min(...rtts) : null;
  const anycastLikely = rtts.length >= 3 && spread !== null && spread < 15 && Math.min(...rtts) < 60;

  return {
    verdict: contradictions.length ? 'FALSIFIED' : rows.length ? 'CONSISTENT' : 'NO_DATA',
    anycastLikely,
    spreadMs: spread === null ? null : round(spread, 1),
    rows,
    contradictions,
    interpretation: anycastLikely
      ? 'Near-uniform low RTT across far-apart probes: this address is anycast. It tells you where TLS terminated, not where inference ran.'
      : contradictions.length
        ? 'At least one measurement is below the fiber floor for the claimed origin. Trust the measurement, not the claim.'
        : 'No physical contradiction. This confirms reachability and plausibility, not the location itself.',
  };
}
