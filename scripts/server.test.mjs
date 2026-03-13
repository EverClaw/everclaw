#!/usr/bin/env node

/**
 * server.test.mjs - Integration tests for the EverClaw Key API
 *
 * Starts the server on a random port, runs tests against the HTTP API,
 * then cleans up. Uses only Node.js built-ins (no test framework needed).
 *
 * Usage:
 *   node scripts/server.test.mjs
 *
 * Environment:
 *   EVERCLAW_API_PORT     - overridden to a random port automatically
 *   EVERCLAW_DB_PATH      - overridden to an in-memory test path
 *   EVERCLAW_ADMIN_SECRET - set to a test value for admin endpoint tests
 */

import { execSync, spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// ─── Test harness ──────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✅ ${message}`);
  } else {
    failed++;
    failures.push(message);
    console.log(`  ❌ ${message}`);
  }
}

function assertEq(actual, expected, message) {
  assert(actual === expected, `${message} (got: ${JSON.stringify(actual)}, expected: ${JSON.stringify(expected)})`);
}

async function request(port, method, path, body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(`http://127.0.0.1:${port}${path}`, opts);
  const data = await res.json();
  return { status: res.status, data };
}

async function requestWithHeaders(port, method, path, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
  const data = await res.json();
  return { status: res.status, data };
}

// ─── Server lifecycle ──────────────────────────────────────────

function startServer(port, dbPath, adminSecret) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', ['server.js'], {
      cwd: join(new URL('.', import.meta.url).pathname, '..'),
      env: {
        ...process.env,
        EVERCLAW_API_PORT: String(port),
        EVERCLAW_DB_PATH: dbPath,
        EVERCLAW_ADMIN_SECRET: adminSecret,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let started = false;

    proc.stdout.on('data', (chunk) => {
      if (!started && chunk.toString().includes('EverClaw Key API on port')) {
        started = true;
        resolve(proc);
      }
    });

    proc.stderr.on('data', (chunk) => {
      const msg = chunk.toString();
      // Ignore non-fatal warnings
      if (!started && msg.includes('Error')) {
        reject(new Error(msg));
      }
    });

    // Timeout if server doesn't start
    setTimeout(() => {
      if (!started) {
        proc.kill();
        reject(new Error('Server failed to start within 10s'));
      }
    }, 10000);
  });
}

// ─── Main ──────────────────────────────────────────────────────

async function main() {
  // Setup
  const port = 30000 + Math.floor(Math.random() * 10000);
  const tmpDir = mkdtempSync(join(tmpdir(), 'everclaw-test-'));
  const dbPath = join(tmpDir, 'test-keys.db');
  const adminSecret = 'test-secret-12345';

  console.log(`\n🧪 EverClaw Key API Tests (port ${port})\n`);

  let server;
  try {
    server = await startServer(port, dbPath, adminSecret);

    // ── Health check ──────────────────────────────────────────
    console.log('Health:');
    {
      const { status, data } = await request(port, 'GET', '/health');
      assertEq(status, 200, 'GET /health returns 200');
      assertEq(data.status, 'ok', 'GET /health returns { status: "ok" }');
    }

    // ── Key request - missing fingerprint ─────────────────────
    console.log('\nKey request - validation:');
    {
      const { status, data } = await request(port, 'POST', '/api/keys/request', {});
      assertEq(status, 400, 'Missing fingerprint returns 400');
      assertEq(data.error, 'missing fingerprint', 'Error message is correct');
    }

    // ── Key request - new device ──────────────────────────────
    console.log('\nKey request - new device:');
    let firstKey;
    {
      const { status, data } = await request(port, 'POST', '/api/keys/request', {
        device_fingerprint: 'test-device-001',
        everclaw_version: '2026.3.16',
      });
      assertEq(status, 201, 'New device returns 201');
      assert(data.api_key && data.api_key.startsWith('evcl_'), 'API key has evcl_ prefix');
      assertEq(data.rate_limit.daily, 1000, 'Daily limit is 1000');
      assertEq(data.rate_limit.remaining, 1000, 'Remaining is 1000 for new key');
      assert(data.expires_at != null, 'Expiry date is set');
      firstKey = data.api_key;
    }

    // ── Key request - same device returns same key ────────────
    console.log('\nKey request - existing device:');
    {
      const { status, data } = await request(port, 'POST', '/api/keys/request', {
        device_fingerprint: 'test-device-001',
      });
      assertEq(status, 200, 'Existing device returns 200 (not 201)');
      assertEq(data.api_key, firstKey, 'Returns the same API key');
    }

    // ── Key request - different device gets different key ─────
    console.log('\nKey request - different device:');
    {
      const { status, data } = await request(port, 'POST', '/api/keys/request', {
        device_fingerprint: 'test-device-002',
      });
      assertEq(status, 201, 'Different device returns 201');
      assert(data.api_key !== firstKey, 'Different device gets a different key');
    }

    // ── Stats - unauthorized ──────────────────────────────────
    console.log('\nAdmin stats - auth:');
    {
      const { status, data } = await request(port, 'GET', '/api/stats');
      assertEq(status, 401, 'Stats without secret returns 401');
    }
    {
      const { status, data } = await requestWithHeaders(port, 'GET', '/api/stats', {
        'x-admin-secret': 'wrong-secret',
      });
      assertEq(status, 401, 'Stats with wrong secret returns 401');
    }

    // ── Stats - authorized ────────────────────────────────────
    console.log('\nAdmin stats - authorized:');
    {
      const { status, data } = await requestWithHeaders(port, 'GET', '/api/stats', {
        'x-admin-secret': adminSecret,
      });
      assertEq(status, 200, 'Stats with correct secret returns 200');
      assertEq(data.total, 2, 'Total keys is 2');
      assertEq(data.active, 2, 'Active keys is 2');
    }

  } finally {
    // Cleanup
    if (server) server.kill();
    try { rmSync(tmpDir, { recursive: true }); } catch {}
  }

  // ── Summary ─────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    failures.forEach((f) => console.log(`  - ${f}`));
  }
  console.log();

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
