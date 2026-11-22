#!/usr/bin/env node
// Build the Encore-style Rust N-API native core and copy the cdylib to
// native/fleet-geo-native.<platform>-<arch>.node so Node loads it with zero deps.
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CRATE_DIR = path.join(ROOT, 'native', 'fleet-geo-native');
const debug = process.argv.includes('--debug');
const profile = debug ? 'debug' : 'release';

const cargoCandidates = [
  process.env.CARGO,
  path.join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'cargo.exe' : 'cargo'),
  'cargo',
].filter(Boolean);
const cargo = cargoCandidates.find((c) => c === 'cargo' || existsSync(c)) ?? 'cargo';

const args = ['build', ...(debug ? [] : ['--release'])];
console.log(`[build:native] ${cargo} ${args.join(' ')} (cwd=${CRATE_DIR})`);
execFileSync(cargo, args, { cwd: CRATE_DIR, stdio: 'inherit' });

const libName =
  process.platform === 'win32'
    ? 'fleet_geo_native.dll'
    : process.platform === 'darwin'
      ? 'libfleet_geo_native.dylib'
      : 'libfleet_geo_native.so';

const src = path.join(CRATE_DIR, 'target', profile, libName);
if (!existsSync(src)) {
  console.error(`[build:native] expected compiled library at ${src}`);
  process.exit(1);
}

const dst = path.join(ROOT, 'native', `fleet-geo-native.${process.platform}-${process.arch}.node`);
copyFileSync(src, dst);
console.log(`[build:native] wrote ${path.relative(ROOT, dst)}`);
