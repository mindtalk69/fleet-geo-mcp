// Geography primitives: dual-stack CIDR math (via src/tcpip.mjs), distance,
// the RTT floor falsifier, region anchors.
export {
  cidrContains,
  cidrContains6,
  compressIpv6,
  expandIpv6Hex,
  intToIpv4,
  ipCidrContains,
  ipFamily,
  ipv4ToInt,
  ipv6ToBigInt,
  parseAddress,
  parseCidr,
  parseCidr6,
  parseIpCidr,
} from './tcpip.mjs';

/** Great-circle distance in km. */
export function haversineKm(a, b) {
  if (!a || !b) return null;
  const R = 6371;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const s =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

// Fiber is ~200,000 km/s, so a round trip costs ~1 ms per 100 km of path length.
// Real paths are longer than the great circle, so measured RTT is normally ABOVE this.
// A measurement far BELOW it is physically impossible => the claimed origin is wrong.
export const MS_PER_KM = 1 / 100;

export function rttFloorMs(distanceKm) {
  return distanceKm === null ? null : distanceKm * MS_PER_KM;
}

export function rttViolates(measuredMs, distanceKm) {
  const floor = rttFloorMs(distanceKm);
  if (floor === null || !Number.isFinite(measuredMs)) return null;
  // 20% slack plus 3 ms keeps us from crying wolf on short paths and jitter.
  const hardFloor = floor * 0.8 - 3;
  return measuredMs < hardFloor ? { floorMs: Number(floor.toFixed(1)), hardFloorMs: Number(hardFloor.toFixed(1)) } : false;
}

// Cloud region anchors. Used only to turn a region name into a coordinate for the
// RTT test. Coordinates are the metro the region serves, not a specific building.
export const REGION_COORDS = {
  // AWS
  'us-east-1': { lat: 38.95, lon: -77.45, place: 'N. Virginia' },
  'us-east-2': { lat: 40.0, lon: -83.02, place: 'Ohio' },
  'us-west-1': { lat: 37.34, lon: -121.89, place: 'N. California' },
  'us-west-2': { lat: 45.87, lon: -119.69, place: 'Oregon' },
  'ca-central-1': { lat: 45.5, lon: -73.57, place: 'Montreal' },
  'sa-east-1': { lat: -23.55, lon: -46.63, place: 'Sao Paulo' },
  'eu-west-1': { lat: 53.35, lon: -6.26, place: 'Dublin' },
  'eu-west-2': { lat: 51.51, lon: -0.13, place: 'London' },
  'eu-west-3': { lat: 48.86, lon: 2.35, place: 'Paris' },
  'eu-central-1': { lat: 50.11, lon: 8.68, place: 'Frankfurt' },
  'eu-central-2': { lat: 47.37, lon: 8.54, place: 'Zurich' },
  'eu-north-1': { lat: 59.33, lon: 18.07, place: 'Stockholm' },
  'eu-south-1': { lat: 45.46, lon: 9.19, place: 'Milan' },
  'ap-southeast-1': { lat: 1.35, lon: 103.82, place: 'Singapore' },
  'ap-southeast-2': { lat: -33.87, lon: 151.21, place: 'Sydney' },
  'ap-southeast-3': { lat: -6.21, lon: 106.85, place: 'Jakarta' },
  'ap-northeast-1': { lat: 35.68, lon: 139.69, place: 'Tokyo' },
  'ap-northeast-2': { lat: 37.57, lon: 126.98, place: 'Seoul' },
  'ap-northeast-3': { lat: 34.69, lon: 135.5, place: 'Osaka' },
  'ap-south-1': { lat: 19.08, lon: 72.88, place: 'Mumbai' },
  'ap-east-1': { lat: 22.32, lon: 114.17, place: 'Hong Kong' },
  'me-south-1': { lat: 26.07, lon: 50.56, place: 'Bahrain' },
  'af-south-1': { lat: -33.92, lon: 18.42, place: 'Cape Town' },
  'il-central-1': { lat: 32.08, lon: 34.78, place: 'Tel Aviv' },
  // GCP
  'us-central1': { lat: 41.26, lon: -95.86, place: 'Iowa' },
  'us-east1': { lat: 33.84, lon: -81.16, place: 'S. Carolina' },
  'us-east4': { lat: 39.04, lon: -77.49, place: 'N. Virginia' },
  'us-west1': { lat: 45.6, lon: -121.18, place: 'Oregon' },
  'us-west2': { lat: 34.05, lon: -118.24, place: 'Los Angeles' },
  'us-west4': { lat: 36.17, lon: -115.14, place: 'Las Vegas' },
  'europe-west1': { lat: 50.45, lon: 3.82, place: 'Belgium' },
  'europe-west2': { lat: 51.51, lon: -0.13, place: 'London' },
  'europe-west3': { lat: 50.11, lon: 8.68, place: 'Frankfurt' },
  'europe-west4': { lat: 53.44, lon: 6.84, place: 'Netherlands' },
  'europe-north1': { lat: 60.57, lon: 27.19, place: 'Finland' },
  'europe-central2': { lat: 52.23, lon: 21.01, place: 'Warsaw' },
  'asia-east1': { lat: 24.05, lon: 120.52, place: 'Taiwan' },
  'asia-east2': { lat: 22.32, lon: 114.17, place: 'Hong Kong' },
  'asia-northeast1': { lat: 35.68, lon: 139.69, place: 'Tokyo' },
  'asia-northeast2': { lat: 34.69, lon: 135.5, place: 'Osaka' },
  'asia-northeast3': { lat: 37.57, lon: 126.98, place: 'Seoul' },
  'asia-south1': { lat: 19.08, lon: 72.88, place: 'Mumbai' },
  'asia-southeast1': { lat: 1.35, lon: 103.82, place: 'Singapore' },
  'asia-southeast2': { lat: -6.21, lon: 106.85, place: 'Jakarta' },
  'australia-southeast1': { lat: -33.87, lon: 151.21, place: 'Sydney' },
  'southamerica-east1': { lat: -23.55, lon: -46.63, place: 'Sao Paulo' },
  'africa-south1': { lat: -26.2, lon: 28.05, place: 'Johannesburg' },
  'me-central1': { lat: 25.29, lon: 51.53, place: 'Doha' },
  // Azure
  eastus: { lat: 36.85, lon: -78.0, place: 'Virginia' },
  eastus2: { lat: 36.85, lon: -78.0, place: 'Virginia' },
  centralus: { lat: 41.59, lon: -93.62, place: 'Iowa' },
  westus2: { lat: 47.6, lon: -122.33, place: 'Washington' },
  westus3: { lat: 33.45, lon: -112.07, place: 'Phoenix' },
  northeurope: { lat: 53.35, lon: -6.26, place: 'Ireland' },
  westeurope: { lat: 52.37, lon: 4.9, place: 'Netherlands' },
  uksouth: { lat: 51.51, lon: -0.13, place: 'London' },
  swedencentral: { lat: 59.33, lon: 18.07, place: 'Sweden' },
  southeastasia: { lat: 1.35, lon: 103.82, place: 'Singapore' },
  japaneast: { lat: 35.68, lon: 139.69, place: 'Tokyo' },
  eastasia: { lat: 22.32, lon: 114.17, place: 'Hong Kong' },
  australiaeast: { lat: -33.87, lon: 151.21, place: 'Sydney' },
  centralindia: { lat: 18.52, lon: 73.86, place: 'Pune' },
  brazilsouth: { lat: -23.55, lon: -46.63, place: 'Sao Paulo' },
  canadacentral: { lat: 43.65, lon: -79.38, place: 'Toronto' },
};

// Country implied by a cloud region name. Needed because a published prefix table
// gives you a region, and a location claim needs a country.
export const REGION_COUNTRY = {
  'us-east-1': 'US', 'us-east-2': 'US', 'us-west-1': 'US', 'us-west-2': 'US',
  'ca-central-1': 'CA', 'sa-east-1': 'BR',
  'eu-west-1': 'IE', 'eu-west-2': 'GB', 'eu-west-3': 'FR', 'eu-central-1': 'DE',
  'eu-central-2': 'CH', 'eu-north-1': 'SE', 'eu-south-1': 'IT',
  'ap-southeast-1': 'SG', 'ap-southeast-2': 'AU', 'ap-southeast-3': 'ID',
  'ap-northeast-1': 'JP', 'ap-northeast-2': 'KR', 'ap-northeast-3': 'JP',
  'ap-south-1': 'IN', 'ap-east-1': 'HK', 'me-south-1': 'BH', 'af-south-1': 'ZA',
  'il-central-1': 'IL',
  'us-central1': 'US', 'us-east1': 'US', 'us-east4': 'US', 'us-west1': 'US',
  'us-west2': 'US', 'us-west4': 'US',
  'europe-west1': 'BE', 'europe-west2': 'GB', 'europe-west3': 'DE', 'europe-west4': 'NL',
  'europe-north1': 'FI', 'europe-central2': 'PL',
  'asia-east1': 'TW', 'asia-east2': 'HK', 'asia-northeast1': 'JP', 'asia-northeast2': 'JP',
  'asia-northeast3': 'KR', 'asia-south1': 'IN', 'asia-southeast1': 'SG',
  'asia-southeast2': 'ID', 'australia-southeast1': 'AU', 'southamerica-east1': 'BR',
  'africa-south1': 'ZA', 'me-central1': 'QA',
  eastus: 'US', eastus2: 'US', centralus: 'US', westus2: 'US', westus3: 'US',
  northeurope: 'IE', westeurope: 'NL', uksouth: 'GB', swedencentral: 'SE',
  southeastasia: 'SG', japaneast: 'JP', eastasia: 'HK', australiaeast: 'AU',
  centralindia: 'IN', brazilsouth: 'BR', canadacentral: 'CA',
};

export const COUNTRY_COORDS = {
  US: { lat: 38.9, lon: -77.0 }, CN: { lat: 31.23, lon: 121.47 }, SG: { lat: 1.35, lon: 103.82 },
  JP: { lat: 35.68, lon: 139.69 }, KR: { lat: 37.57, lon: 126.98 }, TW: { lat: 25.03, lon: 121.56 },
  HK: { lat: 22.32, lon: 114.17 }, IN: { lat: 19.08, lon: 72.88 }, DE: { lat: 50.11, lon: 8.68 },
  IE: { lat: 53.35, lon: -6.26 }, NL: { lat: 52.37, lon: 4.9 }, GB: { lat: 51.51, lon: -0.13 },
  FR: { lat: 48.86, lon: 2.35 }, AU: { lat: -33.87, lon: 151.21 }, BR: { lat: -23.55, lon: -46.63 },
  CA: { lat: 43.65, lon: -79.38 }, AE: { lat: 25.2, lon: 55.27 }, ID: { lat: -6.21, lon: 106.85 },
  FI: { lat: 60.17, lon: 24.94 }, SE: { lat: 59.33, lon: 18.07 }, PL: { lat: 52.23, lon: 21.01 },
  CH: { lat: 47.37, lon: 8.54 }, ES: { lat: 40.42, lon: -3.7 }, IT: { lat: 45.46, lon: 9.19 },
  IL: { lat: 32.08, lon: 34.78 }, ZA: { lat: -26.2, lon: 28.05 }, MX: { lat: 19.43, lon: -99.13 },
  VN: { lat: 21.03, lon: 105.85 }, TH: { lat: 13.76, lon: 100.5 }, MY: { lat: 3.14, lon: 101.69 },
  PH: { lat: 14.6, lon: 120.98 }, NZ: { lat: -36.85, lon: 174.76 },
};

/** Coordinates for a region name, else its country, else null. */
export function coordsFor({ region, country } = {}) {
  if (region) {
    const r = REGION_COORDS[String(region).toLowerCase()];
    if (r) return { ...r, source: 'region' };
  }
  if (country) {
    const c = COUNTRY_COORDS[String(country).toUpperCase()];
    if (c) return { ...c, source: 'country', place: country };
  }
  return null;
}

// Networks that terminate edge traffic across many sites. An IP in one of these is a
// PoP near the caller, so it must never be reported as an inference origin.
export const EDGE_ASNS = {
  13335: 'Cloudflare', 20940: 'Akamai', 54113: 'Fastly', 16509: 'Amazon (AWS/CloudFront)',
  15169: 'Google', 396982: 'Google Cloud', 8075: 'Microsoft/Azure', 22822: 'Limelight',
  60068: 'Datacamp/CDN77', 19551: 'Incapsula/Imperva', 45102: 'Alibaba Cloud CDN',
  132203: 'Tencent Cloud', 396986: 'ByteDance', 13414: 'Twitter/X', 2906: 'Netflix',
  // Own anycast front ends, measured with probe_latency on 2026-11-22: one Anthropic
  // address (160.79.104.10) answered in 1.36 ms from Helsinki and 31.5 ms from Los Angeles,
  // and api.meta.ai answered in 0.67 ms from Helsinki. No single site can do either.
  399358: 'Anthropic (anycast front end)', 32934: 'Meta (edge network)',
};

// Hostname suffixes that name the operator before you ever resolve an IP.
export const HOST_FINGERPRINTS = [
  { re: /\.openai\.azure\.com$|\.cognitiveservices\.azure\.com$/i, operator: 'Microsoft Azure OpenAI', plane: 'origin', note: 'region lives on the Azure resource, not in the hostname' },
  { re: /\.cloudfront\.net$/i, operator: 'AWS CloudFront', plane: 'edge' },
  { re: /\.elb\.amazonaws\.com$|\.compute\.amazonaws\.com$/i, operator: 'AWS (origin load balancer)', plane: 'origin' },
  { re: /\.a2z\.com$/i, operator: 'AWS', plane: 'edge' },
  { re: /\.googleapis\.com$/i, operator: 'Google', plane: 'origin', note: 'check for a region prefix: <region>-aiplatform.googleapis.com' },
  { re: /\.googleusercontent\.com$/i, operator: 'Google', plane: 'edge' },
  { re: /\.azurefd\.net$|\.trafficmanager\.net$/i, operator: 'Azure edge', plane: 'edge' },
  { re: /\.cloudflare\.net$|\.cdn\.cloudflare\.net$/i, operator: 'Cloudflare', plane: 'edge' },
  { re: /\.fastly\.net$/i, operator: 'Fastly', plane: 'edge' },
  { re: /\.akamaiedge\.net$|\.akamai\.net$/i, operator: 'Akamai', plane: 'edge' },
  { re: /\.b-cdn\.net$/i, operator: 'Bunny CDN', plane: 'edge' },
  { re: /\.alicdn\.com$|\.aliyuncs\.com$/i, operator: 'Alibaba Cloud', plane: 'unknown' },
  { re: /\.volces\.com$|\.bytecdntp\.com$/i, operator: 'ByteDance / Volcano Engine', plane: 'unknown' },
];

export function fingerprintHost(host) {
  return HOST_FINGERPRINTS.find((f) => f.re.test(String(host))) ?? null;
}

// Region names can appear anywhere in a hostname, not just at the front:
//   foo-123.ap-southeast-1.elb.amazonaws.com   (AWS load balancer)
//   europe-west4-aiplatform.googleapis.com     (GCP Vertex)
// A known region token embeds a deliberate operator choice, so it is an anchor.
export function findRegionToken(host) {
  const h = String(host).toLowerCase();
  const candidates = new Set();
  for (const m of h.matchAll(/[a-z]{2,}(?:-[a-z]{2,})*-\d+/g)) candidates.add(m[0]);
  for (const m of h.matchAll(/[a-z]{2,}-[a-z]+\d+/g)) candidates.add(m[0]);
  for (const c of candidates) if (REGION_COORDS[c]) return c;
  return null;
}

// Region names encoded directly in a hostname are anchors (tier A), because the
// operator chose that name and DNS resolves it to the regional deployment.
export function regionFromHostname(host) {
  const h = String(host).toLowerCase();
  const patterns = [
    /^bedrock-runtime\.([a-z]{2}-[a-z]+-\d)\./,
    // GCP region ids: us-central1, europe-west4, asia-southeast2, australia-southeast1
    /^([a-z]+(?:-[a-z]+)*\d)-aiplatform\.googleapis\.com$/,
    /^api\.([a-z]{2}-[a-z]+-\d)\.azure\.com$/,
    /^([a-z]{2}-[a-z]+-\d)\./,
  ];
  for (const p of patterns) {
    const m = p.exec(h);
    if (m && REGION_COORDS[m[1]]) return m[1];
  }
  return findRegionToken(h);
}

export const round = (n, d = 1) => (Number.isFinite(n) ? Number(n.toFixed(d)) : null);
