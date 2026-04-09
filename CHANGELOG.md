# EverClaw Changelog

All notable changes to EverClaw are documented here.

## [2026.4.9.1656] - 2026-04-09

### Fixed — Morpheus Gateway Error Unwrapping (Issues #1 & #2)

- **Issue #1: LiteLLM wraps 429 rate limits as HTTP 400** — Venice backend rate limits were returned as HTTP 400 with `providerModelError` wrapper, preventing OpenClaw's retry/fallback chain from triggering.
  - **Fix:** `normalizeLitellmError()` detects wrapped 429 errors (via `code === "429"`, `"RateLimitError"`, `"overloaded"`, `"throttling_error"`) and rewrites to proper HTTP 429.
  - **Impact:** OpenClaw now retries with backoff and triggers model-group fallbacks correctly.

- **Issue #2: LiteLLM "division by zero" server errors wrapped as HTTP 400** — Internal LiteLLM bugs (RPM/TPM math errors when backend reports 0) returned as HTTP 400.
  - **Fix:** Same unwrapping logic detects `code === "500"` or `"division by zero"` and returns HTTP 503 (service unavailable - retryable).

- **New `callGatewayWithRetry()` wrapper** — All 4 gateway call sites now retry transient errors (429, 500, 502, 503) with exponential backoff (1s → 2s → 4s, capped at 10s) before giving up.

- **Streaming safe** — Successful SSE streams pass through immediately; only failed requests trigger retry logic.

- **Zero breaking changes** — Non-provider errors, genuine 400s, and streaming success paths unchanged.

## [2026.4.9.1449] - 2026-04-09 — Windows Detection & OpenClaw URL Fix

### Fixed
- **Windows (Git Bash / MSYS / Cygwin) now shows helpful error** — Instead of a generic "Unsupported OS" message, Windows users are directed to install WSL 2 with a link to Microsoft docs. Consistent messaging across all 4 installer scripts (`install-with-deps.sh`, `install.sh`, `restore-agent.sh`, `setup-ollama.sh`). Thanks to Kyrin for the report.
- **Dead `get.openclaw.ai` URL replaced** — All references updated to the current `openclaw.ai/install.sh` with `--install-method git`. The old `get.openclaw.ai` domain no longer resolves (NXDOMAIN). Fixed in `restore-agent.sh`, `SKILL.md`, and `docs/getting-started/installation.md`.

### Added
- **Explicit platform requirements in docs** — Prerequisites section in SKILL.md and installation.md now clearly states: "Supported platforms: macOS, Linux, Windows via WSL 2."

## [2026.4.9.1353] - 2026-04-09 — OpenClaw v2026.4.9 Pin

### Changed
- **OpenClaw pin** `v2026.4.8` → `v2026.4.9`
  - Dreaming REM backfill lane + `rem-harness --path` for historical daily notes (MemPalace users can now replay old diary entries into Dreams without a second memory stack)
  - Agent idle timeout now correctly inherits `agents.defaults.timeoutSeconds` (we ship 300s) — eliminates false idle-timeout kills for Morpheus P2P users during slow inference; watchdog disabled for cron runs
  - npm packaging fixes for channel plugin deps (validates our Issue #17 Docker workaround)
  - Security & stability: Browser SSRF recheck, dotenv runtime-control blocking, node exec event sanitization, NO_REPLY token stripping, and auto-fallback model override cleared on `/reset`

**Notes**
Pure version pin bump. No breaking changes, no template modifications, no code changes required in EverClaw. Dry run confirmed clean with zero conflicts.

## [2026.4.9.1327] - 2026-04-09 — Docker Channel Plugin Fix

### Fixed
- **Docker image missing channel plugin dependencies** (Issue #17) — OpenClaw v2026.4.8 loads all bundled channel plugins at startup (Telegram, Discord, Slack, Feishu, etc.) but their runtime deps (`grammy`, `@buape/carbon`, `@slack/web-api`, `@larksuiteoapi/node-sdk`, etc.) were not installed in the Docker image. Root cause: OpenClaw's `postinstall-bundled-plugins.mjs` script detects source checkouts (via `src/` + `extensions/` dirs) and skips dep installation. Since the Dockerfile builds from a git clone, these dirs exist and the postinstall silently skips. Fix: remove `src/` and `extensions/` (build-only artifacts, not needed at runtime) after `pnpm build`, then run the postinstall script. This also reduces image size. Thanks to @robkay01 (Bobski) for the detailed bug report.

## [2026.4.8.1910] - 2026-04-08

### Changed
- **OpenClaw pin v2026.4.5 → v2026.4.8** — Dockerfile `OPENCLAW_VERSION` and `docker-compose.yml` `EVERCLAW_VERSION` env updated. SKILL.md version header and diagnostics examples updated to match.
