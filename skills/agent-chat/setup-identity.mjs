#!/usr/bin/env node
/**
 * setup-identity.mjs
 * Generates XMTP keys and stores them securely locally (v1).
 * Inbox ID is registered lazily on first daemon start.
 *
 * Multi-identity support: --agent-id <id> creates per-agent identity
 * at ~/.everclaw/xmtp-<id>/ instead of ~/.everclaw/xmtp/.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { getXmtpDir, resolveAgentId } from './src/paths.mjs';

function parseArgs(args) {
  const parsed = { agentId: undefined, help: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--agent-id' && args[i + 1]) {
      parsed.agentId = args[++i];
    } else if (args[i] === '--help' || args[i] === '-h') {
      parsed.help = true;
    }
  }
  return parsed;
}

function showHelp() {
  console.log(`Usage: node setup-identity.mjs [options]

Options:
  --agent-id <id>   Create identity for a specific agent (e.g. 'alice')
                    Stores in ~/.everclaw/xmtp-<id>/ instead of ~/.everclaw/xmtp/
  --help, -h        Show this help message

Examples:
  node setup-identity.mjs                    # Default host agent identity
  node setup-identity.mjs --agent-id alice   # Alice's buddy bot identity
  node setup-identity.mjs --agent-id bob     # Bob's buddy bot identity

Each agent gets its own:
  - XMTP wallet key (for signing/encryption)
  - DB encryption key (for local SQLite encryption)
  - Separate inbox/outbox directories
  - Separate peer registry and health file
`);
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
  await fs.chmod(dir, 0o700);
}

async function deriveDbKey(privateKey) {
  // Aligned with original PoC for future compatibility
  return crypto.createHash('sha256')
    .update('xmtp-comms-guard:db:' + privateKey)
    .digest('hex');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    showHelp();
    return;
  }

  // Validate agent ID (throws on invalid characters / path traversal)
  const agentId = args.agentId ? resolveAgentId(args.agentId) : undefined;
  const xmtpDir = getXmtpDir(agentId);
  const secretsFile = path.join(xmtpDir, '.secrets.json');
  const identityFile = path.join(xmtpDir, 'identity.json');

  const label = agentId ? `agent '${agentId}'` : 'default (host)';

  console.log(`🔑 Setting up XMTP identity for ${label}...\n`);

  await ensureDir(xmtpDir);

  // Idempotency — skip if identity already exists
  try {
    const existing = JSON.parse(await fs.readFile(identityFile, 'utf8'));
    console.log(`✅ ${label} already configured`);
    console.log(`  Address : ${existing.address}`);
    console.log(`  Path   : ${xmtpDir}`);
    return;
  } catch {}

  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const address = account.address;

  const dbEncryptionKey = await deriveDbKey(privateKey);

  const secrets = { privateKey, dbEncryptionKey };
  await fs.writeFile(secretsFile, JSON.stringify(secrets, null, 2));
  await fs.chmod(secretsFile, 0o600);

  const identityData = {
    address,
    inboxId: null, // set on first daemon start
    network: 'production',
    flavor: process.env.EVERCLAW_FLAVOR || 'everclaw',
    agentId: agentId || null,
    createdAt: new Date().toISOString()
  };

  await fs.writeFile(identityFile, JSON.stringify(identityData, null, 2));

  // Create inbox/outbox directories
  await ensureDir(path.join(xmtpDir, 'inbox'));
  await ensureDir(path.join(xmtpDir, 'outbox'));

  // PII sanity check — ensure no real addresses leaked into source
  const srcDir = path.resolve(path.dirname(new URL(import.meta.url).pathname));
  const srcFiles = (await fs.readdir(path.join(srcDir, 'src')).catch(() => []))
    .filter(f => f.endsWith('.mjs'));
  for (const f of srcFiles) {
    const content = await fs.readFile(path.join(srcDir, 'src', f), 'utf8');
    if (content.includes(address)) {
      console.warn(`⚠️  WARNING: Your address ${address} found in src/${f} — possible PII leak!`);
    }
  }

  console.log(`✅ XMTP identity created for ${label}!`);
  console.log(`  Agent ID : ${agentId || '(host default)'}`);
  console.log(`  Address  : ${address}`);
  console.log(`  Path     : ${xmtpDir}`);
  console.log(`  Secrets  : ${secretsFile} (chmod 600)`);
  console.log('\nRun the daemon once to register your inbox ID on the XMTP network.');

  // Print multi-agent hint if this is not the default
  if (agentId) {
    console.log(`\nTo start this agent's daemon:`);
    console.log(`  bash scripts/setup-agent-chat.sh --agent-id ${agentId}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => { console.error('❌', err.message); process.exit(1); });
}

export { main as setupIdentity };