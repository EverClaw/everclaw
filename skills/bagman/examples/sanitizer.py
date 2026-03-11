"""
Bagman Output Sanitizer (v3)

Apply to ALL agent outputs before sending to any channel.
Catches keys, secrets, seed phrases, sensitive patterns,
and operational metrics that should not leak.

Improvements over v2:
- venice:key<N> references bracketed as [ venice:key<N> ]
- Sensitive metric redaction (balance, threshold, totals, DIEM, etc.)
- Cron summary sanitization (monitoring output scrubbing)
"""

import re
import os
from typing import List, Tuple, Callable, Union, Set
from pathlib import Path


class OutputSanitizer:
    """Sanitize agent outputs to prevent secret leakage."""
    
    # Load full BIP-39 wordlist (2048 words)
    _BIP39_WORDS: Set[str] = None
    
    @classmethod
    def _load_bip39_words(cls) -> Set[str]:
        if cls._BIP39_WORDS is not None:
            return cls._BIP39_WORDS
        
        wordlist_path = Path(__file__).parent / "bip39_wordlist.txt"
        if wordlist_path.exists():
            with open(wordlist_path) as f:
                cls._BIP39_WORDS = {line.strip().lower() for line in f if line.strip()}
        else:
            # Fallback to embedded subset if file missing
            cls._BIP39_WORDS = {
                'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 
                'abstract', 'absurd', 'abuse', 'access', 'accident', 'account', 'accuse',
                'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act', 'action',
                'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address',
                'adjust', 'admit', 'adult', 'advance', 'advice', 'aerobic', 'affair',
                'afford', 'afraid', 'again', 'age', 'agent', 'agree', 'ahead', 'aim',
                'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
                'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already',
                'also', 'alter', 'always', 'amateur', 'amazing', 'among', 'amount',
                'zoo', 'zone', 'zero', 'zebra', 'youth', 'young', 'yellow', 'wrong',
                'write', 'wrist', 'wrestle', 'wreck', 'wrap', 'worth', 'world', 'word',
            }
        return cls._BIP39_WORDS
    
    SECRET_PATTERNS: List[Tuple[str, Union[str, Callable[[re.Match], str]]]] = [
        # Ethereum private keys (32 bytes = 64 hex chars, with 0x prefix)
        (r'0x[a-fA-F0-9]{64}(?![a-fA-F0-9])', '[PRIVATE_KEY_REDACTED]'),
        
        # Raw hex that looks like a private key (64 hex without 0x prefix, word boundary)
        (r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])', '[HEX_KEY_REDACTED]'),
        
        # Split key detection (32 hex chars that could be half a key)
        (r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])', '[PARTIAL_KEY_REDACTED]'),
        
        # Ethereum addresses (20 bytes = 40 hex chars) - truncate, don't hide
        (r'0x[a-fA-F0-9]{40}(?![a-fA-F0-9])', lambda m: f"{m.group()[:6]}...{m.group()[-4:]}"),
        
        # OpenAI keys (multiple formats)
        (r'sk-proj-[a-zA-Z0-9_-]{20,}', '[OPENAI_KEY_REDACTED]'),
        (r'sk-[a-zA-Z0-9]{32,}', '[OPENAI_KEY_REDACTED]'),
        
        # Anthropic keys
        (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{40,}', '[ANTHROPIC_KEY_REDACTED]'),
        
        # Groq keys
        (r'gsk_[a-zA-Z0-9]{20,}', '[GROQ_KEY_REDACTED]'),
        
        # AWS Access Key ID (very specific format)
        (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
        
        # AWS Secret Key (40 chars, but require context to reduce false positives)
        (r'(?i)(?:aws|secret|key|credential)[_\s]*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', '[AWS_SECRET_REDACTED]'),
        
        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', '[GITHUB_PAT_REDACTED]'),
        (r'gho_[a-zA-Z0-9]{36}', '[GITHUB_OAUTH_REDACTED]'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', '[GITHUB_PAT_REDACTED]'),
        (r'ghr_[a-zA-Z0-9]{36}', '[GITHUB_REFRESH_REDACTED]'),
        
        # Google Cloud
        (r'AIza[0-9A-Za-z\-_]{35}', '[GOOGLE_API_KEY_REDACTED]'),
        
        # Slack tokens
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*', '[SLACK_TOKEN_REDACTED]'),
        
        # Discord tokens (Bot and user)
        (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}', '[DISCORD_TOKEN_REDACTED]'),
        
        # Telegram bot tokens (format: botid:secret)
        (r'\d{8,12}:[A-Za-z0-9_-]{30,}', '[TELEGRAM_TOKEN_REDACTED]'),
        
        # Generic API key patterns (with context)
        (r'(?i)(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', r'\1=[REDACTED]'),
        
        # Private key in PEM format
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', '[PEM_PRIVATE_KEY_REDACTED]'),
        
        # JWT tokens (3 base64 parts)
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', '[JWT_TOKEN_REDACTED]'),
        
        # 1Password references (safe to show structure, redact specifics)
        (r'op://[A-Za-z0-9\-_/]+', '[1PASSWORD_REF]'),
        
        # Infura/Alchemy project IDs
        (r'(?i)(infura|alchemy)[_\s]*(?:project[_\s]*)?(?:id|key|secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', r'\1=[REDACTED]'),
        
        # Venice API key references (venice:key1, venice:key2, etc.)
        # Bracket them so they don't leak as usable identifiers
        (r'(?<!\[)\bvenice:key(\d+)\b(?!\s*\])', r'[ venice:key\1 ]'),
    ]
    
    # Patterns for sensitive operational metrics that should not appear in
    # outbound summaries (cron reports, monitoring digests, etc.)
    SENSITIVE_METRIC_PATTERNS: List[Tuple[str, str]] = [
        # Balance figures (e.g., "balance: 42.5", "balance=100 DIEM")
        (r'(?i)\b(balance|bal)\s*[:=]\s*[\d,]+\.?\d*\s*(?:DIEM|MOR|ETH|BTC|USD|USDC|USDT)?', '[BALANCE_REDACTED]'),
        # Threshold values
        (r'(?i)\b(threshold|thresh)\s*[:=]\s*[\d,]+\.?\d*\s*(?:DIEM|MOR|ETH|BTC|USD|USDC|USDT)?', '[THRESHOLD_REDACTED]'),
        # Totals / grand totals
        (r'(?i)\b(total|grand[\s_-]?total)\s*[:=]\s*[\d,]+\.?\d*\s*(?:DIEM|MOR|ETH|BTC|USD|USDC|USDT)?', '[TOTAL_REDACTED]'),
        # DIEM counts (e.g., "194 DIEM", "key1=98 DIEM")
        (r'\b\d+\s*DIEM\b', '[DIEM_REDACTED]'),
        # Explicit "remaining" / "available" / "spent" amounts
        (r'(?i)\b(remaining|available|spent|used)\s*[:=]\s*[\d,]+\.?\d*\s*(?:DIEM|MOR|ETH|BTC|USD|USDC|USDT)?', '[METRIC_REDACTED]'),
    ]
    
    @classmethod
    def sanitize(cls, text: str, redact_metrics: bool = True) -> str:
        """Remove potential secrets from text.
        
        Args:
            text: Raw output text.
            redact_metrics: If True (default), also strip sensitive operational
                            metrics (balances, thresholds, totals, DIEM counts).
                            Disable only for internal debug logging.
        """
        if not text:
            return text
        
        # Apply regex patterns
        for pattern, replacement in cls.SECRET_PATTERNS:
            if callable(replacement):
                text = re.sub(pattern, replacement, text)
            else:
                text = re.sub(pattern, replacement, text)
        
        # Strip sensitive metrics from monitoring / cron outputs
        if redact_metrics:
            for pattern, replacement in cls.SENSITIVE_METRIC_PATTERNS:
                text = re.sub(pattern, replacement, text)
        
        # Check for seed phrases (12 or 24 word sequences)
        text = cls._redact_seed_phrases(text)
        
        return text
    
    @classmethod
    def _redact_seed_phrases(cls, text: str) -> str:
        """Detect and redact potential BIP-39 seed phrases."""
        bip39_words = cls._load_bip39_words()
        words = text.split()
        
        if len(words) < 12:
            return text
        
        # Look for sequences of 12 or 24 BIP-39 words
        for length in [24, 12]:
            if len(words) < length:
                continue
            
            for i in range(len(words) - length + 1):
                sequence = words[i:i + length]
                # Clean punctuation from words for matching
                cleaned = [w.strip('.,;:!?"\'-()[]{}').lower() for w in sequence]
                bip39_count = sum(1 for w in cleaned if w in bip39_words)
                
                # If 90%+ of words are BIP-39, likely a seed phrase
                if bip39_count >= length * 0.9:
                    original_sequence = ' '.join(words[i:i + length])
                    text = text.replace(original_sequence, f'[SEED_PHRASE_{length}_WORDS_REDACTED]')
                    return cls._redact_seed_phrases(text)  # Recurse for multiple phrases
        
        return text
    
    @classmethod
    def contains_secret(cls, text: str) -> Tuple[bool, str]:
        """Check if text likely contains a secret. Returns (bool, reason)."""
        if not text:
            return False, ""
        
        for pattern, _ in cls.SECRET_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return True, f"Pattern match: {pattern[:30]}..."
        
        # Check for seed phrase
        bip39_words = cls._load_bip39_words()
        words = text.split()
        if len(words) >= 12:
            cleaned = [w.strip('.,;:!?"\'-()[]{}').lower() for w in words[:24]]
            bip39_count = sum(1 for w in cleaned if w in bip39_words)
            if bip39_count >= 10:
                return True, f"Potential seed phrase ({bip39_count} BIP-39 words)"
        
        return False, ""
    
    @classmethod
    def scan_file(cls, filepath: str) -> List[Tuple[int, str, str]]:
        """Scan a file for potential secrets. Returns list of (line_number, match, reason)."""
        findings = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    has_secret, reason = cls.contains_secret(line)
                    if has_secret:
                        findings.append((i, line.strip()[:80], reason))
        except Exception as e:
            findings.append((0, f"Error reading file: {e}", "error"))
        return findings


# Test suite
if __name__ == "__main__":
    test_cases = [
        # Private keys
        ("My key is 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", True),
        # Raw hex key (no 0x)
        ("Key: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", True),
        # Split key (32 chars)
        ("First half: 1234567890abcdef1234567890abcdef", True),
        # Addresses (should truncate, not fully redact)
        ("Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e", True),
        # OpenAI
        ("Using sk-proj-abc123def456ghi789jkl012mno345pqr678", True),
        # Anthropic
        ("API key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD", True),
        # AWS with context (should match)
        ("aws_secret_key=AKIAIOSFODNN7EXAMPLE1234567890abcdefgh", True),
        # Random base64 without context (should NOT match - was false positive)
        ("The hash is dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBiYXNl", False),
        # Seed phrase (12 words)
        ("abandon ability able about above absent absorb abstract absurd abuse access accident", True),
        # JWT
        ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", True),
        # Normal text
        ("Normal text without secrets", False),
        # Telegram token
        ("Bot token: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz12345678", True),
    ]
    
    # --- Venice key & metric sanitization tests ---
    cron_summary_tests = [
        # venice:key references should get bracketed
        (
            "Venice API check: venice:key1 has 98 DIEM, venice:key2 has 96 DIEM. Total: 194 DIEM.",
            "[ venice:key1 ]",      # key1 bracketed
            "[ venice:key2 ]",      # key2 bracketed
            "[DIEM_REDACTED]",      # DIEM counts hidden
        ),
        # Balance, threshold, totals in cron output
        (
            "Monitor: balance: 42.5 DIEM, threshold: 10 DIEM, total: 194 DIEM",
            "[BALANCE_REDACTED]",
            "[THRESHOLD_REDACTED]",
            "[TOTAL_REDACTED]",
        ),
        # Already-bracketed venice:key should NOT be double-bracketed
        (
            "Using [ venice:key1 ] for fallback.",
            "[ venice:key1 ]",
            None,
            None,
        ),
        # Remaining / spent metrics (DIEM values get caught by DIEM pattern first)
        (
            "remaining: 50 DIEM, spent: 30 DIEM",
            "[DIEM_REDACTED]",  # DIEM pattern fires first, still sanitized
            None,
            None,
        ),
    ]
    
    print("Output Sanitizer Test (v3)\n" + "=" * 60)
    passed = 0
    failed = 0
    
    # Original secret-detection tests
    for test, should_detect in test_cases:
        has_secret, reason = OutputSanitizer.contains_secret(test)
        sanitized = OutputSanitizer.sanitize(test)
        
        if has_secret == should_detect:
            status = "✅ PASS"
            passed += 1
        else:
            status = "❌ FAIL"
            failed += 1
        
        print(f"\n{status} (expect {'detect' if should_detect else 'ignore'})")
        print(f"   Input:     {test[:60]}{'...' if len(test) > 60 else ''}")
        print(f"   Sanitized: {sanitized[:60]}{'...' if len(sanitized) > 60 else ''}")
        if has_secret:
            print(f"   Reason:    {reason}")
    
    # Cron summary / venice:key / metric tests
    print(f"\n{'=' * 60}")
    print("Cron Summary & Venice Key Sanitization Tests\n" + "-" * 60)
    
    for entry in cron_summary_tests:
        raw = entry[0]
        expected_fragments = [e for e in entry[1:] if e is not None]
        sanitized = OutputSanitizer.sanitize(raw)
        
        all_ok = all(frag in sanitized for frag in expected_fragments)
        # Also ensure raw venice:key<N> (un-bracketed) is gone
        has_raw_venice = re.search(r'(?<!\[)\bvenice:key\d+\b(?!\s*\])', sanitized) is not None
        
        if all_ok and not has_raw_venice:
            status = "✅ PASS"
            passed += 1
        else:
            status = "❌ FAIL"
            failed += 1
        
        print(f"\n{status}")
        print(f"   Input:     {raw[:80]}{'...' if len(raw) > 80 else ''}")
        print(f"   Sanitized: {sanitized[:80]}{'...' if len(sanitized) > 80 else ''}")
        for frag in expected_fragments:
            found = "✓" if frag in sanitized else "✗"
            print(f"   Expected fragment {found}: {frag}")
    
    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed == 0:
        print("All tests passed ✅")
