// Catalog: the only hand-maintained data. Everything else is re-derived live, which is
// why a provider change does not make this tool stale - only documentation facts can
// go stale, and those carry a verifiedAt date that the tool surfaces.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { REGION_COUNTRY } from './geo.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CATALOG_PATH = path.join(ROOT, 'catalog.json');

let catalogCache = null;
let configCache = null;

export function loadCatalog() {
  if (catalogCache) return catalogCache;
  const raw = JSON.parse(readFileSync(path.join(ROOT, 'catalog.json'), 'utf8'));
  raw.providers = (raw.providers ?? []).map((p) => ({
    ...p,
    _re: (p.match ?? []).map((m) => new RegExp(m, 'i')),
  }));
  catalogCache = raw;
  return raw;
}

export function loadConfig() {
  if (configCache) return configCache;
  configCache = JSON.parse(readFileSync(path.join(ROOT, 'config.json'), 'utf8'));
  return configCache;
}

/** Match a model id or a lane/CLI name to a catalog provider. */
export function matchProvider(catalog, { model, lane } = {}) {
  const providers = catalog.providers ?? [];
  if (model) {
    const hit = providers.find((p) => p._re.some((re) => re.test(String(model))));
    if (hit) return { ...hit, matchedBy: 'model' };
  }
  if (lane) {
    const l = String(lane).toLowerCase();
    const hit = providers.find((p) => (p.laneClis ?? []).some((c) => c.toLowerCase() === l));
    if (hit) return { ...hit, matchedBy: 'lane' };
  }
  return null;
}

export function ageDays(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

/** Documentation facts go stale; the tool says so rather than pretending otherwise. */
export function staleness(catalog, provider) {
  const out = [];
  const limit = catalog.staleAfterDays ?? 90;
  const check = (label, iso) => {
    const age = ageDays(iso);
    if (age === null) out.push(`${label}: never verified`);
    else if (age > limit) out.push(`${label}: verified ${age} days ago (limit ${limit})`);
  };
  for (const r of provider?.residency ?? []) check(`residency ${r.region}`, r.verifiedAt);
  for (const a of provider?.facilityAnchors ?? []) check(`anchor ${a.name}`, a.verifiedAt);
  return out;
}

/** Entitlement gate for live probing. Passive lookups are open; traffic is not. */
export function isEntitled(host, config = loadConfig()) {
  const h = String(host).toLowerCase();
  if (config.allowAnyHost) return { allowed: true, reason: 'allowAnyHost' };
  const list = config.entitledHosts ?? [];
  const hit = list.find((e) => {
    const x = String(e).toLowerCase();
    return x.startsWith('*.') ? h.endsWith(x.slice(1)) : h === x || h.endsWith('.' + x);
  });
  return hit
    ? { allowed: true, reason: `listed as entitled: ${hit}` }
    : { allowed: false, reason: `${host} is not in config.json entitledHosts; add it only if the fleet is entitled to call it` };
}

/**
 * Record a documented fact into the catalog.
 *
 * A source URL AND a verbatim quote are mandatory. That is the whole safeguard: an
 * agent may add a fact only by citing where it read it, so the catalog grows by
 * evidence and never by vibes. Re-run locate_model afterwards to see the card move
 * from OPEN/INDICATED to ANCHORED.
 */
export function recordFact(input = {}, { catalogPath = CATALOG_PATH } = {}) {
  const raw = JSON.parse(readFileSync(catalogPath, 'utf8'));
  const key = String(input.provider ?? '').trim().toLowerCase();
  const kind = String(input.kind ?? '').trim().toLowerCase();
  const sourceUrl = String(input.source_url ?? '').trim();
  const quote = String(input.quote ?? '').trim();
  const verifiedAt = String(input.verified_at ?? '').trim() || new Date().toISOString().slice(0, 10);

  const problems = [];
  if (!/^[a-z0-9][a-z0-9_-]{1,31}$/.test(key)) problems.push('provider must be a short lowercase key like "deepseek"');
  if (!['residency', 'facility'].includes(kind)) problems.push('kind must be "residency" or "facility"');
  if (!/^https?:\/\/\S+$/i.test(sourceUrl)) problems.push('source_url must be an http(s) URL');
  if (quote.length < 12) problems.push('quote must be at least 12 characters of text copied from the source');
  if (Number.isNaN(Date.parse(verifiedAt))) problems.push('verified_at must be an ISO date');
  if (problems.length) return { ok: false, error: 'INVALID_FACT', problems };

  let provider = (raw.providers ?? []).find((p) => p.key === key);
  if (!provider) {
    const publisher = String(input.publisher ?? '').trim();
    const match = Array.isArray(input.match) ? input.match.filter((m) => typeof m === 'string' && m) : [];
    if (!publisher || match.length === 0)
      return {
        ok: false,
        error: 'NEW_PROVIDER_NEEDS_MATCH',
        detail: `provider "${key}" is not in the catalog. To add a new one, pass publisher and a non-empty match[] of model-id regexes.`,
      };
    provider = {
      key,
      publisher,
      legalEntity: input.legal_entity ?? null,
      match,
      apiHosts: Array.isArray(input.api_hosts) ? input.api_hosts : [],
      laneClis: [],
      residency: [],
      facilityAnchors: [],
      status: 'verified',
      notes: input.notes ?? 'Added at runtime by record_fact.',
    };
    raw.providers.push(provider);
  }

  let fact;
  if (kind === 'residency') {
    const region = String(input.region ?? '').trim();
    if (!region) return { ok: false, error: 'INVALID_FACT', problems: ['residency requires region'] };
    const country = String(input.country ?? '').trim().toUpperCase() || REGION_COUNTRY[region.toLowerCase()] || '';
    fact = {
      region,
      country: country || null,
      default: (provider.residency ?? []).length === 0,
      source: sourceUrl,
      quote,
      verifiedAt,
      note: input.note ?? null,
    };
    provider.residency = [...(provider.residency ?? []).filter((r) => !(r.region === region && r.source === sourceUrl)), fact];
  } else {
    const name = String(input.name ?? '').trim();
    const city = String(input.city ?? '').trim();
    const country = String(input.country ?? '').trim().toUpperCase();
    if (!name || !city || country.length !== 2)
      return { ok: false, error: 'INVALID_FACT', problems: ['facility requires name, city and a 2-letter country'] };
    fact = { name, city, country, source: sourceUrl, quote, verifiedAt };
    provider.facilityAnchors = [...(provider.facilityAnchors ?? []).filter((a) => a.name !== name), fact];
  }

  provider.status = 'verified';
  raw.lastReviewed = new Date().toISOString().slice(0, 10);

  const tmp = `${catalogPath}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(raw, null, 2)}\n`, 'utf8');
  renameSync(tmp, catalogPath);
  catalogCache = null;

  return {
    ok: true,
    provider: key,
    kind,
    recorded: fact,
    catalogPath,
    totalFacts: (provider.residency ?? []).length + (provider.facilityAnchors ?? []).length,
    next: 'Re-run locate_model for this provider: a verified fact is a tier-A anchor, so the card should move to ANCHORED.',
  };
}

