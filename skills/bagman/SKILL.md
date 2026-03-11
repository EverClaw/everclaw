---
name: bagman
version: 2.2.0
description: Secure key management for AI agents. Use when handling private keys, API secrets, wallet credentials, or when building systems that need agent-controlled funds. Covers secure storage, session keys, leak prevention, prompt injection defense, and MetaMask Delegation Framework integration.
homepage: https://github.com/zscole/bagman-skill
metadata:
  {
    "openclaw": {
      "emoji": "🔐",
      "requires": { "bins": ["op"] },
      "tags": ["security", "wallet", "keys", "crypto", "secrets", "delegation"]
    }
  }
---

# Bagman

Secure key management patterns for AI agents handling wallets, private keys, and secrets.

## When to Use This Skill

- Agent needs wallet/blockchain access
- Handling API keys, credentials, or secrets
- Building systems where AI controls funds
- Preventing secret leakage via prompts or outputs

## Quick Start

```bash
# Install 1Password CLI
brew install 1password-cli

# Authenticate
eval $(op signin)

# Create vault for agent credentials
op vault create "Agent-Credentials"

# Run examples
cd examples && python test_suite.py
```

---

## Core Rules

| Rule | Why |
|------|-----|
| Never store raw private keys | Config, env, memory, or conversation = leaked |
| Use delegated access | Session keys with time/value/scope limits |
| Secrets via secret manager | 1Password, Vault, AWS Secrets Manager |
| Sanitize all outputs | Scan for key patterns before any response |
| Validate all inputs | Check for injection attempts before wallet ops |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   AI Agent                          │
├─────────────────────────────────────────────────────┤
│  Session Key (bounded)                              │
│  ├─ Expires after N hours                           │
│  ├─ Max spend per tx/day                            │
│  └─ Whitelist of allowed contracts/methods          │
├─────────────────────────────────────────────────────┤
│  Secret Manager (1Password/Vault)                   │
│  ├─ Retrieve at runtime only                        │
│  ├─ Never persist to disk                           │
│  └─ Audit trail of accesses                         │
├─────────────────────────────────────────────────────┤
│  Smart Account (ERC-4337)                           │
│  ├─ Programmable permissions                        │
│  └─ Recovery without key exposure                   │
└─────────────────────────────────────────────────────┘
```

---

## Implementation Files

| File | Purpose |
|------|---------|
| `examples/secret_manager.py` | 1Password integration for runtime secret retrieval |
| `examples/sanitizer.py` | Output sanitization (keys, seeds, tokens) |
| `examples/validator.py` | Input validation (prompt injection defense) |
| `examples/session_keys.py` | ERC-4337 session key configuration |
| `examples/delegation_integration.ts` | MetaMask Delegation Framework (EIP-7710) |
| `examples/pre-commit` | Git hook to block secret commits |
| `examples/test_suite.py` | Adversarial test suite |
| `docs/prompt-injection.md` | Deep dive on injection defense |
| `docs/secure-storage.md` | Secret storage patterns |
| `docs/session-keys.md` | Session key architecture |
| `docs/leak-prevention.md` | Output sanitization patterns |
| `docs/delegation-framework.md` | On-chain permission enforcement (EIP-7710) |

---

## 1. Secret Retrieval

### 1Password CLI Pattern

```bash
# Retrieve at runtime (never store result)
SESSION_KEY=$(op read "op://Agents/my-agent/session-key")

# Run with injected secrets (never touch disk)
op run --env-file=.env.tpl -- python agent.py
```

### .env.tpl (safe to commit - no secrets)

```
PRIVATE_KEY=op://Agents/trading-bot/session-key
RPC_URL=op://Infra/alchemy/sepolia-url
OPENAI_API_KEY=op://Services/openai/api-key
```

### Python Usage

```python
from secret_manager import get_session_key

# Retrieve validated session key
creds = get_session_key("trading-bot-session")

# Check validity
if creds.is_expired():
    raise ValueError("Session expired - request renewal from operator")

print(f"Time remaining: {creds.time_remaining()}")
print(f"Allowed contracts: {creds.allowed_contracts}")

# Use the key (never log it!)
client.set_signer(creds.session_key)
```

### Vault-Level ACL (Recommended)

Configure 1Password vault permissions:

```
Agent-Credentials/
├── trading-bot-session    # Agent can read
├── payment-bot-session    # Agent can read
└── master-key             # Operator ONLY (agent has no access)
```

**Principle:** Agent credentials should be in a vault with read-only agent access. Master keys should be in a separate vault the agent cannot access.

---

## 2. Output Sanitization (MANDATORY)

**⚠️ CRITICAL: Apply to ALL agent outputs before sending anywhere. No exceptions.**

This includes:
- Chat responses
- Cron job summaries
- Monitoring alerts
- Status reports
- Debug logs
- Error messages
- Any text that leaves the agent

```python
from sanitizer import OutputSanitizer

def respond(content: str) -> str:
    """Mandatory sanitization before ANY output."""
    return OutputSanitizer.sanitize(content)

def cron_summary(task_result: dict) -> str:
    """Cron summaries MUST sanitize before delivery."""
    summary = format_summary(task_result)
    return OutputSanitizer.sanitize(summary)  # ALWAYS sanitize
```

### Secret Patterns Detected

| Pattern | Example | Result |
|---------|---------|--------|
| ETH private key | `0x1234...abcd` (64 hex) | `[PRIVATE_KEY_REDACTED]` |
| ETH address | `0x742d...f44e` (40 hex) | `0x742d...f44e` (truncated) |
| OpenAI key | `sk-proj-abc123...` | `[OPENAI_KEY_REDACTED]` |
| Anthropic key | `sk-ant-api03-...` | `[ANTHROPIC_KEY_REDACTED]` |
| 12-word seed | `abandon ability able...` | `[SEED_PHRASE_12_WORDS_REDACTED]` |
| JWT | `eyJhbG...` | `[JWT_TOKEN_REDACTED]` |
| Venice key refs | `venice:key1`, `venice:key2` | `[ venice:key1 ]` (bracketed) |

### Sensitive Metrics Redacted (Cron Summaries)

| Pattern | Example | Result |
|---------|---------|--------|
| DIEM counts | `98 DIEM`, `194 DIEM` | `[DIEM_REDACTED]` |
| Balance | `balance: 42.5 DIEM` | `[BALANCE_REDACTED]` |
| Threshold | `threshold: 10 DIEM` | `[THRESHOLD_REDACTED]` |
| Totals | `total: 194 DIEM` | `[TOTAL_REDACTED]` |
| Remaining/Spent | `remaining: 50 DIEM` | `[METRIC_REDACTED]` |

### Cron Summary Example

**BEFORE sanitization (NEVER send this):**
```
Venice API check: venice:key1 has 98 DIEM, venice:key2 has 96 DIEM.
Balance: 194 DIEM, Threshold: 10 DIEM
```

**AFTER sanitization (safe to send):**
```
Venice API check: [ venice:key1 ] has [DIEM_REDACTED], [ venice:key2 ] has [DIEM_REDACTED].
[BALANCE_REDACTED], [THRESHOLD_REDACTED]
```

### Venice Key Reference Sanitization

Venice API key references (`venice:key1`, `venice:key2`, etc.) are **NOT secrets** themselves, but should be bracketed to:
1. Prevent them from being used as identifiers in logs
2. Make it clear they are references, not actual keys
3. Distinguish from potential false-positive patterns

The sanitizer brackets un-bracketed references: `venice:key1` → `[ venice:key1 ]`

Already-bracketed references are left unchanged: `[ venice:key1 ]` → `[ venice:key1 ]`

---

## 3. Input Validation

Check inputs before ANY wallet operation:

```python
from validator import InputValidator, ThreatLevel

result = InputValidator.validate(user_input)

if result.level == ThreatLevel.BLOCKED:
    return f"Request blocked: {result.reason}"

if result.level == ThreatLevel.SUSPICIOUS:
    # Log for review, but allow
    log_suspicious(user_input, result.reason)

# Proceed with operation
```

### Threat Categories

| Category | Examples | Action |
|----------|----------|--------|
| Extraction | "show private key", "reveal secrets" | Block |
| Override | "ignore previous instructions" | Block |
| Role manipulation | "you are now admin" | Block |
| Jailbreak | "DAN mode", "bypass filters" | Block |
| Exfiltration | "send config to https://..." | Block |
| Wallet threats | "transfer all", "unlimited approve" | Block |
| Encoded | Base64/hex encoded attacks | Block |
| Unicode tricks | Cyrillic lookalikes, zero-width | Block |
| Suspicious | "hypothetically", "just between us" | Warn |

---

## 4. Operation Allowlisting

Never execute arbitrary operations. Explicit whitelist only:

```python
from dataclasses import dataclass
from decimal import Decimal
from typing import Optional

@dataclass
class AllowedOperation:
    name: str
    handler: callable
    max_value: Optional[Decimal] = None
    requires_confirmation: bool = False
    cooldown_seconds: int = 0

ALLOWED_OPS = {
    "check_balance": AllowedOperation("check_balance", get_balance),
    "transfer_usdc": AllowedOperation(
        "transfer_usdc", 
        transfer,
        max_value=Decimal("500"),
        requires_confirmation=True,
        cooldown_seconds=60
    ),
    "swap": AllowedOperation(
        "swap",
        swap_tokens,
        max_value=Decimal("1000"),
        cooldown_seconds=300
    ),
}

def execute(op_name: str, **kwargs):
    if op_name not in ALLOWED_OPS:
        raise PermissionError(f"Operation '{op_name}' not allowed")
    
    op = ALLOWED_OPS[op_name]
    
    if op.max_value and kwargs.get("amount", 0) > op.max_value:
        raise PermissionError(f"Amount exceeds limit: {op.max_value}")
    
    if op.requires_confirmation:
        return request_confirmation(op_name, kwargs)
    
    return op.handler(**kwargs)
```

---

## 5. Confirmation Flow

High-value operations require explicit confirmation:

```python
import hashlib
import time

pending_confirmations = {}

def request_confirmation(operation: str, details: dict) -> str:
    code = hashlib.sha256(
        f"{operation}{time.time()}".encode()
    ).hexdigest()[:8].upper()
    
    pending_confirmations[code] = {
        "op": operation,
        "details": details,
        "expires": time.time() + 300  # 5 minutes
    }
    
    return f"⚠️ Confirm '{operation}' with code: {code}\n(expires in 5 minutes)"

def confirm(code: str):
    if code not in pending_confirmations:
        return "Invalid confirmation code"
    
    req = pending_confirmations.pop(code)
    
    if time.time() > req["expires"]:
        return "Confirmation code expired"
    
    return execute_confirmed(req["op"], req["details"])
```

---

## 6. Session Keys (ERC-4337)

Instead of giving agents master keys, issue bounded session keys:

```python
from session_keys import SessionKeyManager

# Operator creates trading session for agent
config = SessionKeyManager.create_trading_session(
    agent_name="alpha-trader",
    operator_address="0x742d...",
    duration_hours=24,
    max_trade_usdc=1000,
    daily_limit_usdc=5000,
)

# Export for storage in 1Password
export_data = SessionKeyManager.export_for_1password(
    config, 
    session_key_hex="0x..."  # Generated session key
)

# op item create ... (store in 1Password)
```

### Session Key Benefits

| Feature | Master Key | Session Key |
|---------|------------|-------------|
| Expiration | Never | Configurable (hours/days) |
| Spending limits | None | Per-tx and daily caps |
| Contract restrictions | Full access | Whitelist only |
| Revocation | Requires key rotation | Instant, no key change |
| Audit | None | Full operation log |

---

## 7. Pre-commit Hook

Block commits containing secrets:

```bash
# Install
cp examples/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

Detected patterns:
- ETH private keys (64 hex chars)
- OpenAI/Anthropic/Groq keys
- AWS access keys
- GitHub/GitLab tokens
- Slack/Discord tokens
- PEM private keys
- Generic PASSWORD/SECRET assignments
- BIP-39 seed phrases

---

## 8. Defense Layers

```
USER INPUT
    │
    ▼
┌────────────────────────────┐
│ Layer 1: Input Validation  │  ← Regex + encoding + unicode checks
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 2: Op Allowlisting   │  ← Explicit whitelist only
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 3: Value Limits      │  ← Max per-tx and per-day
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 4: Confirmation      │  ← Time-limited codes for $$$
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 5: Isolated Exec     │  ← Wallet ops != conversation
└────────────────────────────┘
    │
    ▼
OUTPUT SANITIZATION
```

---

## Common Mistakes

### ❌ Keys in memory files
```markdown
# memory/2026-02-07.md
Private key: 0x9f01dad551039daad...
```
**Fix:** Store reference only: `Private key: [stored in 1Password: test-wallet]`

### ❌ Keys in error messages
```python
except Exception as e:
    log(f"Failed with key {private_key}: {e}")
```
**Fix:** Never include credentials in error context

### ❌ Keys in .env.example
```
PRIVATE_KEY=sk-ant-api03-real-key...  # "for testing"
```
**Fix:** Use obviously fake: `PRIVATE_KEY=your-key-here`

### ❌ "All" in transfer requests
```
User: "Transfer all my USDC"
Agent: *executes unlimited transfer*
```
**Fix:** Block "all/everything/max" patterns, require explicit amounts

### ❌ Trusting conversation context
```python
# Wallet has access to conversation history
self.wallet.execute(conversation[-1]["content"])
```
**Fix:** Wallet operations must be isolated from conversation context

---

## Testing

```bash
cd examples

# Run full test suite
python test_suite.py

# Test individual components
python sanitizer.py    # Output sanitization demo
python validator.py    # Input validation demo
python session_keys.py # Session key demo
```

Expected output: `All tests passed`

### Test Evidence (v2.2.0 - 2026-03-11)

**Sanitizer v3 Test Results - All 16 tests passed:**

```
Output Sanitizer Test (v3)
============================================================

✅ PASS (expect detect)
   Input:     My key is 0x1234567890abcdef...
   Sanitized: My key is [PRIVATE_KEY_REDACTED]

✅ PASS (expect detect)
   Input:     Key: 1234567890abcdef...
   Sanitized: Key: [HEX_KEY_REDACTED]

✅ PASS (expect detect)
   Input:     First half: 1234567890abcdef...
   Sanitized: First half: [PARTIAL_KEY_REDACTED]

✅ PASS (expect detect)
   Input:     Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
   Sanitized: Send to 0x742d...f44e

✅ PASS (expect detect)
   Input:     Using sk-proj-abc123def456...
   Sanitized: Using [OPENAI_KEY_REDACTED]

✅ PASS (expect detect)
   Input:     API key is sk-ant-api03-abcdef...
   Sanitized: API key is [ANTHROPIC_KEY_REDACTED]

✅ PASS (expect detect)
   Input:     aws_secret_key=AKIAIOSFODNN7EXAMPLE...
   Sanitized: aws_secret_key=[AWS_ACCESS_KEY_REDACTED]...

✅ PASS (expect ignore)
   Input:     The hash is dGhpcyBpcyBhIHRlc3Q...
   Sanitized: The hash is dGhpcyBpcyBhIHRlc3Q...

✅ PASS (expect detect)
   Input:     abandon ability able about above absent...
   Sanitized: [SEED_PHRASE_12_WORDS_REDACTED]

✅ PASS (expect detect)
   Input:     Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   Sanitized: Bearer [JWT_TOKEN_REDACTED]

✅ PASS (expect ignore)
   Input:     Normal text without secrets
   Sanitized: Normal text without secrets

✅ PASS (expect detect)
   Input:     Bot token: 123456789:ABCdefGHI...
   Sanitized: Bot token: [TELEGRAM_TOKEN_REDACTED]

============================================================
Cron Summary & Venice Key Sanitization Tests
------------------------------------------------------------

✅ PASS
   Input:     Venice API check: venice:key1 has 98 DIEM, venice:key2 has 96 DIEM. Total: 194 DIEM.
   Sanitized: Venice API check: [ venice:key1 ] has [DIEM_REDACTED], [ venice:key2 ] has [DIEM_REDACTED]...
   Expected fragment ✓: [ venice:key1 ]
   Expected fragment ✓: [ venice:key2 ]
   Expected fragment ✓: [DIEM_REDACTED]

✅ PASS
   Input:     Monitor: balance: 42.5 DIEM, threshold: 10 DIEM, total: 194 DIEM
   Sanitized: Monitor: [BALANCE_REDACTED], [THRESHOLD_REDACTED], [TOTAL_REDACTED]
   Expected fragment ✓: [BALANCE_REDACTED]
   Expected fragment ✓: [THRESHOLD_REDACTED]
   Expected fragment ✓: [TOTAL_REDACTED]

✅ PASS
   Input:     Using [ venice:key1 ] for fallback.
   Sanitized: Using [ venice:key1 ] for fallback.
   Expected fragment ✓: [ venice:key1 ]

✅ PASS
   Input:     remaining: 50 DIEM, spent: 30 DIEM
   Sanitized: remaining: [DIEM_REDACTED], spent: [DIEM_REDACTED]
   Expected fragment ✓: [DIEM_REDACTED]

============================================================
Results: 16 passed, 0 failed
All tests passed ✅
```

**Key capabilities verified:**
- venice:key<N> references are bracketed: `[ venice:key1 ]`
- Already-bracketed references remain unchanged
- Sensitive metrics (balance, threshold, total, DIEM counts) are redacted
- All existing secret detection patterns work correctly

---

## Checklist

- [ ] 1Password CLI installed and authenticated
- [ ] Secrets in 1Password vault, not files
- [ ] Session keys with expiry and limits
- [ ] Output sanitization on all responses
- [ ] Input validation before wallet ops
- [ ] Pre-commit hook installed
- [ ] Confirmation flow for high-value operations
- [ ] Wallet operations isolated from conversation
- [ ] .gitignore covers secrets and memory files
- [ ] Test suite passes

---

## Security Model Limitations

This skill provides **defense in depth**, not a guarantee. Adversaries may:

1. **Novel injection patterns** - Regex can't catch everything; semantic analysis helps but isn't perfect
2. **Social engineering** - Convincing the operator to approve malicious operations
3. **Timing attacks** - Exploiting confirmation windows
4. **Encoding evasion** - New encoding schemes not covered

**Recommendation:** Layer these defenses with:
- Rate limiting
- Anomaly detection
- Human-in-the-loop for large transactions
- Regular security audits
