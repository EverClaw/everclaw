/**
 * test/fixtures/setup-test-env.mjs
 * Creates an isolated temp directory with fake identity/secrets for testing.
 * Sets AGENT_CHAT_XMTP_DIR so all modules use the temp dir instead of ~/.everclaw/xmtp.
 *
 * Multi-identity support: setupTestEnvForAgent('alice') creates a separate
 * temp directory at xmtp-alice with its own identity.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

let testDir;
const agentDirs = {};

export async function setupTestEnv() {
  testDir = path.join(os.tmpdir(), `agent-chat-test-${crypto.randomBytes(6).toString('hex')}`);
  await fs.mkdir(testDir, { recursive: true });
  await fs.mkdir(path.join(testDir, 'inbox'), { recursive: true });
  await fs.mkdir(path.join(testDir, 'outbox'), { recursive: true });

  // Set env BEFORE any module imports read it
  process.env.AGENT_CHAT_XMTP_DIR = testDir;
  process.env.EVERCLAW_HOME = path.dirname(testDir); // parent dir for agent paths

  // Write fake secrets
  const fakePrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const fakeDbKey = crypto.createHash('sha256')
    .update('xmtp-comms-guard:db:' + fakePrivateKey)
    .digest('hex');

  await fs.writeFile(
    path.join(testDir, '.secrets.json'),
    JSON.stringify({ privateKey: fakePrivateKey, dbEncryptionKey: fakeDbKey }, null, 2)
  );

  // Write fake identity
  await fs.writeFile(
    path.join(testDir, 'identity.json'),
    JSON.stringify({
      address: '0x' + crypto.randomBytes(20).toString('hex'),
      inboxId: null,
      network: 'production',
      flavor: 'everclaw-test',
      createdAt: new Date().toISOString()
    }, null, 2)
  );

  return testDir;
}

/**
 * Create a test identity for a specific agent (multi-identity testing).
 * Returns the agent's XMTP directory path.
 */
export async function setupTestEnvForAgent(agentId) {
  const baseDir = process.env.EVERCLAW_HOME || path.join(os.tmpdir(), `agent-chat-test-home-${crypto.randomBytes(4).toString('hex')}`);
  const agentDir = path.join(baseDir, `xmtp-${agentId}`);
  await fs.mkdir(agentDir, { recursive: true });
  await fs.mkdir(path.join(agentDir, 'inbox'), { recursive: true });
  await fs.mkdir(path.join(agentDir, 'outbox'), { recursive: true });

  // Generate unique identity for this agent
  const fakePrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const fakeDbKey = crypto.createHash('sha256')
    .update('xmtp-comms-guard:db:' + fakePrivateKey)
    .digest('hex');

  await fs.writeFile(
    path.join(agentDir, '.secrets.json'),
    JSON.stringify({ privateKey: fakePrivateKey, dbEncryptionKey: fakeDbKey }, null, 2)
  );

  await fs.writeFile(
    path.join(agentDir, 'identity.json'),
    JSON.stringify({
      address: '0x' + crypto.randomBytes(20).toString('hex'),
      inboxId: null,
      network: 'production',
      flavor: 'everclaw-test',
      agentId: agentId,
      createdAt: new Date().toISOString()
    }, null, 2)
  );

  agentDirs[agentId] = agentDir;
  return agentDir;
}

export async function teardownTestEnv() {
  // Clean up default test dir
  if (testDir) {
    await fs.rm(testDir, { recursive: true, force: true });
    delete process.env.AGENT_CHAT_XMTP_DIR;
    testDir = null;
  }

  // Clean up agent dirs
  for (const agentId of Object.keys(agentDirs)) {
    await fs.rm(agentDirs[agentId], { recursive: true, force: true }).catch(() => {});
  }
  Object.keys(agentDirs).forEach(k => delete agentDirs[k]);

  if (process.env.EVERCLAW_HOME && process.env.EVERCLAW_HOME.includes('agent-chat-test')) {
    await fs.rm(process.env.EVERCLAW_HOME, { recursive: true, force: true }).catch(() => {});
    delete process.env.EVERCLAW_HOME;
  }
}

export function getTestDir() {
  return testDir;
}