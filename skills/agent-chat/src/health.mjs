/**
 * src/health.mjs — status.json for OpenClaw heartbeat + message counter.
 * Multi-identity: writes health to per-agent XMTP directory.
 */

import fs from 'node:fs/promises';
import { getHealthFilePath } from './paths.mjs';

let getStatusFn; // cached import

/**
 * Atomic message counter — incremented by router on every routed message (all tiers).
 */
export const messageCounter = {
  _count: 0,
  increment() { this._count++; },
  get value() { return this._count; },
};

/**
 * Write health status file for a given agent.
 * @param {string} status - 'running', 'stopped', or 'error'
 * @param {string} [agentId] - Agent identifier for multi-identity.
 */
export async function writeHealthFile(status, agentId) {
  if (!getStatusFn) {
    const mod = await import('./identity.mjs');
    getStatusFn = mod.getStatus;
  }

  const identityStatus = await getStatusFn(agentId);
  const health = {
    status,
    timestamp: new Date().toISOString(),
    inboxId: identityStatus.inboxId || 'unknown',
    messagesProcessed: messageCounter.value,
  };

  if (agentId) {
    health.agentId = agentId;
  }

  await fs.writeFile(getHealthFilePath(agentId), JSON.stringify(health, null, 2));
}