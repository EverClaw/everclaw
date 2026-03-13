# Contributing to EverClaw

Thanks for your interest in contributing to EverClaw! This project connects OpenClaw agents to the Morpheus decentralized inference network - every contribution helps make decentralized AI more accessible.

## Quick Start

1. **Fork** the repo on GitHub
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/EverClaw.git
   cd EverClaw
   ```
3. **Create a branch** for your work:
   ```bash
   git checkout -b feat/your-feature-name
   ```
4. **Make your changes**, commit, and push
5. **Open a Pull Request** against `main`

## Development Setup

### Prerequisites

- Node.js v18+
- Git
- Docker (optional, for container builds)

### Running the Key API Server Locally

```bash
npm install
node server.js
# Server starts on port 3000 (or EVERCLAW_API_PORT)
```

### Running Tests

```bash
# Shell script syntax check
bash -n scripts/install-with-deps.sh
bash -n scripts/install.sh

# Wallet tests
node scripts/everclaw-wallet.test.mjs
```

### Testing the Installer

```bash
# Check-only mode (no changes)
bash scripts/install-with-deps.sh --check-only

# Full help
bash scripts/install-with-deps.sh --help
```

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code restructuring (no behavior change)
- `test:` - Adding or updating tests
- `chore:` - Maintenance, CI, tooling

Examples:
```
feat: add Linux systemd support for proxy installer
fix: resolve session count parsing in balance.sh
docs: add CONTRIBUTING.md with development setup guide
refactor: format server.js for readability
```

## What to Contribute

### Good First Issues

- Documentation improvements (README, inline comments, guides)
- Shell script portability fixes (macOS vs Linux differences)
- Test coverage for existing scripts
- Typo fixes and formatting cleanup

### Impactful Contributions

- New platform support (Windows/WSL, FreeBSD)
- Additional test coverage for `setup.mjs` and `server.js`
- Monitoring and observability improvements
- Security hardening (input validation, rate limiting)

### Before You Start

- Check [open issues](https://github.com/EverClaw/EverClaw/issues) for existing discussions
- For larger changes, open an issue first to discuss the approach
- Keep PRs focused - one logical change per PR

## Code Style

- JavaScript: ES modules (`import`/`export`), single quotes, semicolons
- Shell: `bash` with `set -euo pipefail` where practical
- Add JSDoc comments for exported functions
- Keep files readable - avoid minification in source

## Security

- **Never commit secrets, API keys, or wallet private keys**
- Use environment variables for all sensitive configuration
- Run `bash scripts/pii-scan.sh` before committing to check for accidental PII
- Report security vulnerabilities privately per [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
