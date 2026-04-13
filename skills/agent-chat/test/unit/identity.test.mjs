/**
 * test/unit/identity.test.mjs
 * Tests identity loading, secret management, inboxId persistence, and multi-identity support.
 * Uses isolated temp directory — never touches real ~/.everclaw/xmtp.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setupTestEnv, setupTestEnvForAgent, teardownTestEnv, getTestDir } from '../fixtures/setup-test-env.mjs';

// MUST set env before importing modules
let identity;

describe('Identity Module', () => {
  before(async () => {
    await setupTestEnv();
    // Dynamic import after env is set
    identity = await import('../../src/identity.mjs');
  });

  after(async () => {
    await teardownTestEnv();
  });

  it('loads secrets with correct env var names', async () => {
    const secrets = await identity.loadSecrets();
    assert.ok(secrets.XMTP_WALLET_KEY, 'should have XMTP_WALLET_KEY');
    assert.ok(secrets.XMTP_WALLET_KEY.startsWith('0x'), 'wallet key should be hex');
    assert.ok(secrets.XMTP_DB_ENCRYPTION_KEY, 'should have XMTP_DB_ENCRYPTION_KEY');
    assert.strictEqual(secrets.XMTP_DB_ENCRYPTION_KEY.length, 64, 'DB key should be 64 hex chars');
    assert.strictEqual(secrets.XMTP_ENV, 'production');
  });

  it('loads full identity with metadata + secrets + dbPath', async () => {
    const id = await identity.loadIdentity();
    assert.ok(id.metadata, 'should have metadata');
    assert.ok(id.metadata.address, 'should have address');
    assert.ok(id.metadata.address.startsWith('0x'), 'address should be hex');
    assert.strictEqual(id.metadata.network, 'production');
    assert.strictEqual(id.metadata.flavor, 'everclaw-test');
    assert.ok(id.secrets, 'should have secrets');
    assert.strictEqual(id.dbPath, getTestDir());
  });

  it('inboxId starts as null (lazy registration)', async () => {
    const id = await identity.loadIdentity();
    assert.strictEqual(id.metadata.inboxId, null);
  });

  it('saves and persists inboxId', async () => {
    await identity.saveInboxId('test-inbox-abc123');
    const id = await identity.loadIdentity();
    assert.strictEqual(id.metadata.inboxId, 'test-inbox-abc123');

    // Verify it persisted to disk
    const raw = JSON.parse(await fs.readFile(path.join(getTestDir(), 'identity.json'), 'utf8'));
    assert.strictEqual(raw.inboxId, 'test-inbox-abc123');
  });

  it('getStatus returns ready with address and inboxId', async () => {
    const status = await identity.getStatus();
    assert.strictEqual(status.status, 'ready');
    assert.ok(status.address);
    assert.strictEqual(status.inboxId, 'test-inbox-abc123');
  });

  it('warns when wallet key has wrong length', async () => {
    const secretsPath = path.join(getTestDir(), '.secrets.json');
    const backup = await fs.readFile(secretsPath, 'utf8');

    // Write a truncated key
    const badSecrets = JSON.parse(backup);
    badSecrets.privateKey = '0xshort';
    await fs.writeFile(secretsPath, JSON.stringify(badSecrets));

    // Capture console.warn
    const warnings = [];
    const origWarn = console.warn;
    console.warn = (...args) => warnings.push(args.join(' '));

    await identity.loadSecrets();

    console.warn = origWarn;
    assert.ok(warnings.some(w => w.includes('WARNING') && w.includes('expected 66')),
      'should warn about wrong key length');

    // Restore
    await fs.writeFile(secretsPath, backup);
  });

  it('getStatus returns missing when secrets file is gone', async () => {
    const secretsPath = path.join(getTestDir(), '.secrets.json');
    const backup = await fs.readFile(secretsPath, 'utf8');
    await fs.unlink(secretsPath);

    const status = await identity.getStatus();
    assert.strictEqual(status.status, 'missing');
    assert.ok(status.error);

    // Restore
    await fs.writeFile(secretsPath, backup);
  });
});

// ─── Multi-Identity Tests ──────────────────────────────────────────────────

describe('Identity Module — Multi-Identity', () => {
  let aliceDir;

  before(async () => {
    // Re-setup default test env so loadIdentity() can find it
    await setupTestEnv();
    // Create a test identity for 'alice' agent
    aliceDir = await setupTestEnvForAgent('alice');
  });

  after(async () => {
    await teardownTestEnv();
  });

  it('loads identity for a specific agent', async () => {
    const id = await identity.loadIdentity('alice');
    assert.ok(id.metadata, 'should have metadata');
    assert.ok(id.metadata.address, 'should have address');
    assert.strictEqual(id.metadata.agentId, 'alice');
    assert.ok(id.dbPath.includes('xmtp-alice'), `dbPath should contain xmtp-alice, got ${id.dbPath}`);
  });

  it('loads secrets for a specific agent', async () => {
    const secrets = await identity.loadSecrets('alice');
    assert.ok(secrets.XMTP_WALLET_KEY, 'should have XMTP_WALLET_KEY');
    assert.ok(secrets.XMTP_WALLET_KEY.startsWith('0x'), 'wallet key should be hex');
    assert.strictEqual(secrets.XMTP_DB_ENCRYPTION_KEY.length, 64, 'DB key should be 64 hex chars');
  });

  it('saves inboxId for a specific agent', async () => {
    await identity.saveInboxId('alice-inbox-456', 'alice');
    const id = await identity.loadIdentity('alice');
    assert.strictEqual(id.metadata.inboxId, 'alice-inbox-456');
  });

  it('getStatus returns agentId when specified', async () => {
    const status = await identity.getStatus('alice');
    assert.strictEqual(status.status, 'ready');
    assert.strictEqual(status.agentId, 'alice');
  });

  it('getStatus returns missing for non-existent agent', async () => {
    const status = await identity.getStatus('nonexistent');
    assert.strictEqual(status.status, 'missing');
    assert.strictEqual(status.agentId, 'nonexistent');
  });

  it('default and alice identities are isolated', async () => {
    const defaultId = await identity.loadIdentity();
    const aliceId = await identity.loadIdentity('alice');
    assert.notStrictEqual(defaultId.metadata.address, aliceId.metadata.address,
      'default and alice should have different addresses');
    assert.notStrictEqual(defaultId.dbPath, aliceId.dbPath,
      'default and alice should have different dbPaths');
  });
});