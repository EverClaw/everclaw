/**
 * src/identity.mjs
 * Loads XMTP identity + secrets for Agent.create / createFromEnv.
 * DB path is the directory only (SDK auto-names files).
 *
 * Multi-identity support: reads AGENT_CHAT_AGENT_ID from env to determine
 * which agent's identity to load. Each agent stores its data in
 * ~/.everclaw/xmtp-<id>/ (or ~/.everclaw/xmtp/ for the default host agent).
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { getXmtpDir } from './paths.mjs';

/**
 * Load secrets as real XMTP env-var names (used by daemon)
 * @param {string} [agentId] - Agent identifier for multi-identity.
 */
export async function loadSecrets(agentId) {
  const xmtpDir = getXmtpDir(agentId);
  const secretsFile = path.join(xmtpDir, '.secrets.json');
  const data = JSON.parse(await fs.readFile(secretsFile, 'utf8'));

  // Runtime validation — catch truncated or malformed keys early
  if (data.privateKey && data.privateKey.length !== 66) {
    console.warn(`[Identity] WARNING: XMTP_WALLET_KEY length is ${data.privateKey.length}, expected 66 (0x + 64 hex)`);
  }

  return {
    XMTP_WALLET_KEY: data.privateKey,
    XMTP_DB_ENCRYPTION_KEY: data.dbEncryptionKey,
    XMTP_ENV: 'production'
  };
}

/**
 * Full identity for runtime
 * @param {string} [agentId] - Agent identifier for multi-identity.
 */
export async function loadIdentity(agentId) {
  const xmtpDir = getXmtpDir(agentId);
  const identityFile = path.join(xmtpDir, 'identity.json');
  const metadata = JSON.parse(await fs.readFile(identityFile, 'utf8'));
  const secrets = await loadSecrets(agentId);

  return {
    metadata,
    secrets,
    dbPath: xmtpDir,
    agentId: agentId || null
  };
}

/**
 * Called by daemon after first Agent.create() to store the real inboxId
 * @param {string} inboxId - The XMTP inbox ID received from the network.
 * @param {string} [agentId] - Agent identifier for multi-identity.
 */
export async function saveInboxId(inboxId, agentId) {
  const xmtpDir = getXmtpDir(agentId);
  const identityFile = path.join(xmtpDir, 'identity.json');
  const metadata = JSON.parse(await fs.readFile(identityFile, 'utf8'));
  metadata.inboxId = inboxId;
  await fs.writeFile(identityFile, JSON.stringify(metadata, null, 2));
}

/**
 * Quick status for CLI/health
 * @param {string} [agentId] - Agent identifier for multi-identity.
 */
export async function getStatus(agentId) {
  try {
    const id = await loadIdentity(agentId);
    return {
      status: 'ready',
      address: id.metadata.address,
      inboxId: id.metadata.inboxId || 'pending-first-start',
      agentId: id.metadata.agentId || null
    };
  } catch (err) {
    return { status: 'missing', error: err.message, agentId: agentId || null };
  }
}

export default { loadIdentity, loadSecrets, saveInboxId, getStatus };