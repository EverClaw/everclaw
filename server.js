/**
 * EverClaw Key API Server
 *
 * Manages API key lifecycle for EverClaw inference access.
 * Keys are issued per device fingerprint, auto-renewed on expiry,
 * and rate-limited to 1,000 requests/day by default.
 *
 * Environment variables:
 *   EVERCLAW_API_PORT    - Server port (default: 3000)
 *   EVERCLAW_DB_PATH     - SQLite database path (default: ./data/keys.db)
 *   EVERCLAW_ADMIN_SECRET - Secret for admin endpoints (required for /api/stats)
 */

import express from 'express';
import Database from 'better-sqlite3';
import { randomBytes } from 'crypto';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import cors from 'cors';

// ─── Path setup ────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Configuration ─────────────────────────────────────────────

const PORT = process.env.EVERCLAW_API_PORT || 3000;
const DB_PATH = process.env.EVERCLAW_DB_PATH || join(__dirname, 'data', 'keys.db');
const SECRET = process.env.EVERCLAW_ADMIN_SECRET;

/** Key expiry window: 30 days from now. */
const KEY_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

/** Default daily rate limit per key. */
const DEFAULT_DAILY_LIMIT = 1000;

// ─── Database ──────────────────────────────────────────────────

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id                  INTEGER PRIMARY KEY,
    api_key             TEXT UNIQUE,
    device_fingerprint  TEXT UNIQUE,
    everclaw_version    TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at          DATETIME NOT NULL,
    last_renewed_at     DATETIME,
    request_count_today INTEGER DEFAULT 0,
    request_count_total INTEGER DEFAULT 0,
    last_request_at     DATETIME,
    last_reset_at       DATETIME,
    rate_limit_daily    INTEGER DEFAULT ${DEFAULT_DAILY_LIMIT},
    is_revoked          BOOLEAN DEFAULT 0,
    revoke_reason       TEXT
  )
`);

// ─── Helpers ───────────────────────────────────────────────────

/** Generate a prefixed API key. */
const generateKey = () => 'evcl_' + randomBytes(16).toString('hex');

/** Return an ISO timestamp 30 days from now. */
const expiryFromNow = () => new Date(Date.now() + KEY_EXPIRY_MS).toISOString();

// ─── Express app ───────────────────────────────────────────────

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

// ─── Routes ────────────────────────────────────────────────────

/** Health check. */
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

/**
 * POST /api/keys/request
 *
 * Request or renew an API key for a device.
 * - If the fingerprint already has a key, return it (renewing if expired).
 * - If the fingerprint is new, issue a fresh key.
 * - Revoked keys return 403.
 *
 * Body: { device_fingerprint: string, everclaw_version?: string }
 */
app.post('/api/keys/request', (req, res) => {
  const { device_fingerprint, everclaw_version } = req.body;

  if (!device_fingerprint) {
    return res.status(400).json({ error: 'missing fingerprint' });
  }

  // Look up existing key for this device
  let existing = db
    .prepare('SELECT * FROM keys WHERE device_fingerprint = ?')
    .get(device_fingerprint);

  if (existing) {
    // Revoked keys cannot be renewed
    if (existing.is_revoked) {
      return res.status(403).json({ error: 'revoked' });
    }

    // Auto-renew expired keys
    if (new Date(existing.expires_at) < new Date()) {
      db.prepare(
        'UPDATE keys SET expires_at = ?, last_renewed_at = CURRENT_TIMESTAMP WHERE id = ?'
      ).run(expiryFromNow(), existing.id);

      existing = db.prepare('SELECT * FROM keys WHERE id = ?').get(existing.id);
    }

    return res.json({
      api_key: existing.api_key,
      expires_at: existing.expires_at,
      rate_limit: {
        daily: existing.rate_limit_daily,
        remaining: existing.rate_limit_daily - existing.request_count_today,
      },
    });
  }

  // Issue a new key
  const apiKey = generateKey();

  db.prepare(
    'INSERT INTO keys (api_key, device_fingerprint, everclaw_version, expires_at) VALUES (?, ?, ?, ?)'
  ).run(apiKey, device_fingerprint, everclaw_version || null, expiryFromNow());

  console.log('[ISSUE]', apiKey.substring(0, 12));

  res.status(201).json({
    api_key: apiKey,
    expires_at: expiryFromNow(),
    rate_limit: {
      daily: DEFAULT_DAILY_LIMIT,
      remaining: DEFAULT_DAILY_LIMIT,
    },
  });
});

/**
 * GET /api/stats
 *
 * Admin-only endpoint returning total and active key counts.
 * Requires the x-admin-secret header to match EVERCLAW_ADMIN_SECRET.
 */
app.get('/api/stats', (req, res) => {
  if (!SECRET || req.headers['x-admin-secret'] !== SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const stats = db
    .prepare(
      'SELECT COUNT(*) as total, SUM(CASE WHEN is_revoked = 0 THEN 1 ELSE 0 END) as active FROM keys'
    )
    .get();

  res.json(stats);
});

// ─── Start ─────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`EverClaw Key API on port ${PORT}`);
});
