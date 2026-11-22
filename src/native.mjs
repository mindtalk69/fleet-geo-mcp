// Optional Rust N-API loader with automatic pure-JS fallback.
//
// Encore-style architecture: the Node.js MCP server stays zero-dependency at runtime
// and loads the compiled Rust `.node` cdylib directly via createRequire when present
// (or when `FLEET_GEO_NATIVE=0` is not set). If no native binary is built for the
// current platform/arch, every caller transparently falls back to pure JS.
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

let loaded = undefined;
let loadError = null;
let loadedPath = null;

function candidatePaths() {
  const dir = path.join(ROOT, 'native');
  return [
    path.join(dir, `fleet-geo-native.${process.platform}-${process.arch}.node`),
    path.join(dir, 'fleet-geo-native.node'),
  ];
}

export function getNative() {
  if (loaded !== undefined) return loaded;
  if (process.env.FLEET_GEO_NATIVE === '0') {
    loaded = null;
    loadError = 'disabled via FLEET_GEO_NATIVE=0';
    return null;
  }
  for (const p of candidatePaths()) {
    if (!existsSync(p)) continue;
    try {
      loaded = require(p);
      loadedPath = p;
      return loaded;
    } catch (e) {
      loadError = e?.message ?? String(e);
    }
  }
  loaded = null;
  return null;
}

export function nativeStatus() {
  const n = getNative();
  if (n?.runtimeInfo) {
    return { ...n.runtimeInfo(), loaded: true, binary: path.relative(ROOT, loadedPath) };
  }
  return {
    engine: 'js-fallback',
    version: null,
    platform: process.platform,
    arch: process.arch,
    capabilities: [],
    loaded: false,
    binary: null,
    reason: loadError ?? 'native .node addon not built (run: npm run build:native)',
  };
}
