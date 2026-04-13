#!/usr/bin/env node
/**
 * daemon.mjs
 * Always-on XMTP daemon entry point. Managed by launchd (macOS) or systemd (Linux).
 * Handles graceful shutdown (SIGTERM/SIGINT) and health file updates.
 *
 * Multi-identity support: --agent-id <id> flag or AGENT_CHAT_AGENT_ID env var
 * starts a daemon for a specific buddy bot identity.
 */

import { loadIdentity } from './src/identity.mjs';
import { startAgent, stopAgent } from './src/agent.mjs';
import { startBridge, stopBridge } from './src/bridge.mjs';
import { writeHealthFile } from './src/health.mjs';
import { resolveAgentId, validateAgentId } from './src/paths.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';

// Parse --agent-id from CLI args
function parseArgs(args) {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--agent-id' && args[i + 1]) {
      return args[++i];
    }
  }
  return undefined;
}

// Shallow merge config — acceptable for v1
async function loadConfig() {
  const configPath = path.resolve(path.dirname(new URL(import.meta.url).pathname), 'config', 'default.json');
  try {
    return JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch {
    console.warn('[Daemon] No config found, using defaults');
    return { xmtp: {} };
  }
}

let healthInterval;
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  const label = agentLabel();
  console.log(`[Daemon ${label}] ${signal} received — shutting down`);

  clearInterval(healthInterval);
  stopBridge();
  await stopAgent();
  await writeHealthFile('stopped', agentId_);

  console.log(`[Daemon ${label}] Clean shutdown complete`);
  process.exit(0);
}

let agentId_ = undefined;

function agentLabel() {
  return agentId_ || 'host';
}

async function main() {
  // Resolve agent ID: CLI arg > env var > undefined (default host)
  const cliAgentId = parseArgs(process.argv.slice(2));
  try {
    agentId_ = resolveAgentId(cliAgentId);
  } catch (err) {
    console.error(`[Daemon] Invalid agent ID: ${err.message}`);
    process.exit(3); // exit code 3 = identity/key error
  }
  const label = agentLabel();

  console.log(`[Daemon ${label}] Starting XMTP agent-chat daemon...`);

  const config = await loadConfig();
  const identity = await loadIdentity(agentId_);

  console.log(`[Daemon ${label}] Identity loaded: ${identity.metadata.address}`);
  console.log(`[Daemon ${label}] Flavor: ${identity.metadata.flavor}`);
  if (agentId_) {
    console.log(`[Daemon ${label}] Agent ID: ${agentId_}`);
  }

  // Start agent with full middleware chain
  await startAgent(identity, config);

  // Start filesystem bridge
  startBridge(config, agentId_);

  // Health file loop
  await writeHealthFile('running', agentId_);
  const healthMs = config.xmtp?.health?.updateIntervalMs || 5000;
  healthInterval = setInterval(() => writeHealthFile('running', agentId_), healthMs);

  console.log(`[Daemon ${label}] Ready — listening for messages`);
}

// Graceful shutdown handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Unhandled errors — write health and exit
process.on('uncaughtException', async (err) => {
  console.error(`[Daemon ${agentLabel()}] Uncaught exception:`, err);
  await writeHealthFile('error', agentId_).catch(() => {});
  process.exit(1);
});

main().catch(async (err) => {
  console.error(`[Daemon ${agentLabel()}] Fatal startup error:`, err);
  await writeHealthFile('error', agentId_).catch(() => {});
  process.exit(3); // Exit code 3 = identity/key error (per error handling table)
});