/**
 * src/paths.mjs
 * Shared path helpers — single source of truth for XMTP directory structure.
 * All path functions are runtime (not module-level const) for testability.
 *
 * Multi-identity support: pass agentId to derive per-agent paths.
 *   getXmtpDir('alice')  → ~/.everclaw/xmtp-alice/
 *   getXmtpDir()         → ~/.everclaw/xmtp/  (default, backward compatible)
 *
 * When running in a per-agent daemon, AGENT_CHAT_AGENT_ID is set in the
 * service file env. Callers can omit agentId and it resolves from env.
 *
 * Env var AGENT_CHAT_XMTP_DIR always wins for the default (host) agent.
 * Per-agent paths always resolve from EVERCLAW_HOME to prevent isolation bypass.
 */

import path from 'node:path';
import os from 'node:os';

const EVERCLAW_HOME = () => process.env.EVERCLAW_HOME || path.join(os.homedir(), '.everclaw');

/**
 * Allowed characters in agent IDs: lowercase a-z, digits, hyphens.
 * Prevents directory traversal, service injection, and filesystem issues.
 * Must start with alphanumeric, 1-63 chars total.
 */
const AGENT_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

/**
 * Validate an agent ID for safety.
 * @param {string} agentId - Raw agent ID string.
 * @returns {string} Validated agent ID.
 * @throws {Error} If agent ID contains invalid characters, path traversal, or is too long.
 */
export function validateAgentId(agentId) {
  if (typeof agentId !== 'string') {
    throw new Error(`Invalid agent ID: must be a string, got ${typeof agentId}`);
  }
  // Prevent directory traversal (.., /, \, etc.)
  if (agentId.includes('..') || agentId.includes('/') || agentId.includes(path.sep)) {
    throw new Error(`Invalid agent ID: "${agentId}" contains path traversal characters`);
  }
  if (!AGENT_ID_RE.test(agentId)) {
    throw new Error(
      `Invalid agent ID: "${agentId}". Must match ${AGENT_ID_RE.toString()} ` +
      '(1-63 chars, lowercase alphanumeric + hyphens, must start with alphanumeric)'
    );
  }
  return agentId;
}

/**
 * Resolve the effective agent ID.
 * Priority: explicit arg > AGENT_CHAT_AGENT_ID env var > undefined (default host).
 * Validates the result if non-empty.
 * @param {string} [agentId] - Explicit agent ID override.
 * @returns {string|undefined} The validated agent ID, or undefined for the default host agent.
 */
export function resolveAgentId(agentId) {
  const effective = agentId || process.env.AGENT_CHAT_AGENT_ID || undefined;
  if (effective) {
    return validateAgentId(effective);
  }
  return undefined;
}

/**
 * Get the XMTP data directory for a given agent.
 * @param {string} [agentId] - Agent identifier (e.g. 'alice'). Resolves from env if omitted.
 * @returns {string} Absolute path to the agent's XMTP directory.
 */
export function getXmtpDir(agentId) {
  // Env override only applies to the default (host) agent
  // Per-agent paths always resolve from EVERCLAW_HOME (isolation guarantee)
  if (process.env.AGENT_CHAT_XMTP_DIR && !agentId) {
    return process.env.AGENT_CHAT_XMTP_DIR;
  }
  const effectiveId = resolveAgentId(agentId);
  const suffix = effectiveId ? `xmtp-${effectiveId}` : 'xmtp';
  return path.join(EVERCLAW_HOME(), suffix);
}

export function getInboxDir(agentId) {
  return path.join(getXmtpDir(agentId), 'inbox');
}

export function getOutboxDir(agentId) {
  return path.join(getXmtpDir(agentId), 'outbox');
}

export function getPeersFilePath(agentId) {
  return path.join(getXmtpDir(agentId), 'peers.json');
}

export function getHealthFilePath(agentId) {
  return path.join(getXmtpDir(agentId), 'health.json');
}

export function getGroupsFilePath(agentId) {
  return path.join(getXmtpDir(agentId), 'groups.json');
}

/**
 * Get the service name for a given agent (launchd).
 * @param {string} [agentId] - Agent identifier.
 * @returns {string} Service label, e.g. 'com.everclaw.agent-chat.alice' or 'com.everclaw.agent-chat'.
 */
export function getLaunchdLabel(agentId) {
  const effectiveId = resolveAgentId(agentId);
  return effectiveId ? `com.everclaw.agent-chat.${effectiveId}` : 'com.everclaw.agent-chat';
}

/**
 * Get the service name for a given agent (systemd).
 * @param {string} [agentId] - Agent identifier.
 * @returns {string} Unit name, e.g. 'everclaw-agent-chat-alice' or 'everclaw-agent-chat'.
 */
export function getSystemdName(agentId) {
  const effectiveId = resolveAgentId(agentId);
  // systemd unit names cannot contain dots
  return effectiveId ? `everclaw-agent-chat-${effectiveId}` : 'everclaw-agent-chat';
}