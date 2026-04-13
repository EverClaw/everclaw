import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';

describe('Paths Module', async () => {
  let paths;
  const origXmtpDir = process.env.AGENT_CHAT_XMTP_DIR;
  const origAgentId = process.env.AGENT_CHAT_AGENT_ID;
  const origHome = process.env.EVERCLAW_HOME;

  before(async () => {
    paths = await import('../../src/paths.mjs');
  });

  after(() => {
    // Restore original env vars
    if (origXmtpDir !== undefined) process.env.AGENT_CHAT_XMTP_DIR = origXmtpDir;
    else delete process.env.AGENT_CHAT_XMTP_DIR;
    if (origAgentId !== undefined) process.env.AGENT_CHAT_AGENT_ID = origAgentId;
    else delete process.env.AGENT_CHAT_AGENT_ID;
    if (origHome !== undefined) process.env.EVERCLAW_HOME = origHome;
    else delete process.env.EVERCLAW_HOME;
  });

  // ─── Default (host agent) paths ────────────────────────────────────────

  it('getXmtpDir returns env override when set', () => {
    process.env.AGENT_CHAT_XMTP_DIR = '/tmp/test-xmtp';
    delete process.env.AGENT_CHAT_AGENT_ID;
    assert.equal(paths.getXmtpDir(), '/tmp/test-xmtp');
  });

  it('defaults to ~/.everclaw/xmtp when env not set', () => {
    delete process.env.AGENT_CHAT_XMTP_DIR;
    delete process.env.AGENT_CHAT_AGENT_ID;
    const dir = paths.getXmtpDir();
    assert.ok(dir.endsWith('.everclaw/xmtp'), `Expected path ending with .everclaw/xmtp, got ${dir}`);
  });

  it('getInboxDir is child of xmtpDir', () => {
    delete process.env.AGENT_CHAT_XMTP_DIR;
    delete process.env.AGENT_CHAT_AGENT_ID;
    process.env.EVERCLAW_HOME = '/tmp/test-home';
    assert.equal(paths.getInboxDir(), '/tmp/test-home/xmtp/inbox');
  });

  it('getOutboxDir is child of xmtpDir', () => {
    assert.equal(paths.getOutboxDir(), '/tmp/test-home/xmtp/outbox');
  });

  it('getPeersFilePath is child of xmtpDir', () => {
    assert.equal(paths.getPeersFilePath(), '/tmp/test-home/xmtp/peers.json');
  });

  it('getHealthFilePath is child of xmtpDir', () => {
    assert.equal(paths.getHealthFilePath(), '/tmp/test-home/xmtp/health.json');
  });

  it('getGroupsFilePath is child of xmtpDir', () => {
    assert.equal(paths.getGroupsFilePath(), '/tmp/test-home/xmtp/groups.json');
  });

  // ─── Multi-identity paths ──────────────────────────────────────────────

  it('getXmtpDir with agentId returns per-agent directory', () => {
    delete process.env.AGENT_CHAT_XMTP_DIR;
    process.env.EVERCLAW_HOME = '/tmp/test-home';
    assert.equal(paths.getXmtpDir('alice'), '/tmp/test-home/xmtp-alice');
  });

  it('getXmtpDir with different agentId returns different directories', () => {
    assert.equal(paths.getXmtpDir('alice'), '/tmp/test-home/xmtp-alice');
    assert.equal(paths.getXmtpDir('bob'), '/tmp/test-home/xmtp-bob');
    assert.equal(paths.getXmtpDir(), '/tmp/test-home/xmtp');
  });

  it('getXmtpDir env var overrides default but NOT per-agent', () => {
    process.env.AGENT_CHAT_XMTP_DIR = '/tmp/override';
    process.env.EVERCLAW_HOME = '/tmp/test-home';
    // Env var applies to default (no agentId)
    assert.equal(paths.getXmtpDir(), '/tmp/override');
    // But per-agent paths always resolve from EVERCLAW_HOME
    assert.equal(paths.getXmtpDir('alice'), '/tmp/test-home/xmtp-alice');
    delete process.env.AGENT_CHAT_XMTP_DIR;
  });

  it('getInboxDir with agentId returns per-agent inbox', () => {
    assert.equal(paths.getInboxDir('alice'), '/tmp/test-home/xmtp-alice/inbox');
  });

  it('getOutboxDir with agentId returns per-agent outbox', () => {
    assert.equal(paths.getOutboxDir('alice'), '/tmp/test-home/xmtp-alice/outbox');
  });

  it('getPeersFilePath with agentId returns per-agent peers', () => {
    assert.equal(paths.getPeersFilePath('alice'), '/tmp/test-home/xmtp-alice/peers.json');
  });

  it('getHealthFilePath with agentId returns per-agent health', () => {
    assert.equal(paths.getHealthFilePath('alice'), '/tmp/test-home/xmtp-alice/health.json');
  });

  // ─── resolveAgentId ────────────────────────────────────────────────────

  it('resolveAgentId returns explicit arg over env var', () => {
    process.env.AGENT_CHAT_AGENT_ID = 'from-env';
    assert.equal(paths.resolveAgentId('from-arg'), 'from-arg');
  });

  it('resolveAgentId falls back to env var when no arg', () => {
    process.env.AGENT_CHAT_AGENT_ID = 'from-env';
    assert.equal(paths.resolveAgentId(), 'from-env');
  });

  it('resolveAgentId returns undefined when no arg and no env', () => {
    delete process.env.AGENT_CHAT_AGENT_ID;
    assert.equal(paths.resolveAgentId(), undefined);
  });

  // ─── Service naming ────────────────────────────────────────────────────

  it('getLaunchdLabel returns default for no agent', () => {
    delete process.env.AGENT_CHAT_AGENT_ID;
    assert.equal(paths.getLaunchdLabel(), 'com.everclaw.agent-chat');
  });

  it('getLaunchdLabel returns agent-specific for agent', () => {
    assert.equal(paths.getLaunchdLabel('alice'), 'com.everclaw.agent-chat.alice');
  });

  it('getSystemdName returns default for no agent', () => {
    assert.equal(paths.getSystemdName(), 'everclaw-agent-chat');
  });

  it('getSystemdName returns agent-specific for agent', () => {
    assert.equal(paths.getSystemdName('alice'), 'everclaw-agent-chat-alice');
  });

  it('all paths update dynamically when env changes', () => {
    process.env.AGENT_CHAT_XMTP_DIR = '/tmp/a';
    assert.equal(paths.getXmtpDir(), '/tmp/a');
    process.env.AGENT_CHAT_XMTP_DIR = '/tmp/b';
    assert.equal(paths.getXmtpDir(), '/tmp/b');
  });

  // ─── Agent ID validation ────────────────────────────────────────────

  it('validates well-formed agent IDs', () => {
    assert.equal(paths.validateAgentId('alice'), 'alice');
    assert.equal(paths.validateAgentId('bob-123'), 'bob-123');
    assert.equal(paths.validateAgentId('a1b2c3'), 'a1b2c3');
    assert.equal(paths.validateAgentId('a'), 'a'); // single char
  });

  it('rejects empty agent IDs', () => {
    assert.throws(() => paths.validateAgentId(''), /Invalid agent ID/);
  });

  it('rejects agent IDs with path traversal', () => {
    assert.throws(() => paths.validateAgentId('..'), /path traversal/);
    assert.throws(() => paths.validateAgentId('../etc'), /path traversal/);
    assert.throws(() => paths.validateAgentId('alice/../../etc'), /path traversal/);
  });

  it('rejects agent IDs with uppercase, spaces, dots, underscores', () => {
    assert.throws(() => paths.validateAgentId('Alice'), /Invalid agent ID/);
    assert.throws(() => paths.validateAgentId('alice bob'), /Invalid agent ID/);
    assert.throws(() => paths.validateAgentId('alice.bob'), /Invalid agent ID/);
    assert.throws(() => paths.validateAgentId('alice_bob'), /Invalid agent ID/);
  });

  it('rejects agent IDs starting with hyphens', () => {
    assert.throws(() => paths.validateAgentId('-alice'), /Invalid agent ID/);
  });

  it('rejects overly long agent IDs', () => {
    const longId = 'a' + 'bc'.repeat(32); // 65 chars
    assert.throws(() => paths.validateAgentId(longId), /Invalid agent ID/);
  });

  it('rejects non-string agent IDs', () => {
    assert.throws(() => paths.validateAgentId(123), /Invalid agent ID/);
    assert.throws(() => paths.validateAgentId(null), /Invalid agent ID/);
    assert.throws(() => paths.validateAgentId(undefined), /Invalid agent ID/);
  });});