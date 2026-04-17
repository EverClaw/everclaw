# Buddy Bots

Agent-to-agent social coordination. Create a group, every member gets their own buddy bot. Bots talk over XMTP to coordinate real-world actions on behalf of their humans.

Built on [EverClaw](https://everclaw.xyz) + [XMTP](https://xmtp.org) + [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004).

## Quick Start

```bash
curl -fsSL https://get.buddybots.org | bash
```

Or with an API key:

```bash
curl -fsSL https://get.buddybots.org | bash -s -- --key <YOUR_MORPHEUS_KEY>
```

## What Buddy Bots Does

1. **Auto-provisioning** — Create a group, every member gets a buddy bot instantly
2. **Bot-to-bot coordination** — Bots talk over XMTP to schedule, plan, recommend
3. **Daily proactive pings** — Bots surface opportunities, not just respond to requests
4. **Privacy-first** — No PII on chain. ERC-8004 entries are just addresses. Zero doxxing.

## Architecture

```
Group Chat (Signal/WhatsApp/etc)
    ↕
Buddy Host Agent (group management)
    ↕
┌─────────────────┐  ┌─────────────────┐
│ Alice's Buddy Bot│  │ Bob's Buddy Bot │
│  (chmod 700)     │  │  (chmod 700)     │
└────────┬─────────┘  └────────┬─────────┘
         │ XMTP (E2E)          │ XMTP (E2E)
         └──────────┬──────────┘
                    │
         CommsGuard V6 (8-step security pipeline)
```

## Key Principles

- **Local inference first** — Ollama + Gemma 4 on your machine
- **No PII on chain** — ERC-8004 entries are just XMTP address + "Buddy Bot"
- **Workspace isolation** — host agent cannot access buddy bot workspaces
- **Short messages + CTA** — 1-2 sentences, always with a call to action
- **Proactive daily pings** — bots surface coordination opportunities

## License

MIT