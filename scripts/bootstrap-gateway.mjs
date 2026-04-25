#!/usr/bin/env node

/**
 * Monorepo wrapper — forwards to packages/core/scripts/bootstrap-gateway.mjs
 *
 * This file exists only in the monorepo root. Composed flavor repos have the
 * real bootstrap-gateway.mjs at this path (copied from packages/core/scripts/
 * by flavor-compose.sh).
 *
 * All CLI arguments (e.g., --key, --test, --status) pass through automatically
 * via process.argv.
 */

import { existsSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const coreScript = resolve(__dirname, '..', 'packages', 'core', 'scripts', 'bootstrap-gateway.mjs');

if (!existsSync(coreScript)) {
  console.error('❌ Cannot find bootstrap-gateway.mjs');
  console.error('   Expected: packages/core/scripts/bootstrap-gateway.mjs');
  console.error('');
  console.error('   If you installed EverClaw from a flavor repo (e.g., everclaw.xyz),');
  console.error('   this wrapper should not exist. Please reinstall or report this issue.');
  process.exit(1);
}

await import(pathToFileURL(coreScript).href);
