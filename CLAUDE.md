# sec-scan Client

> **About this file:** CLAUDE.md is for agent guidance - architectural decisions, rules, conventions, and gotchas that can't be inferred from reading code. Focus on the "why", not the "what".

## Overview
Go CLI client for the sec-scan.ai PHP security scanner. Collects PHP files from a directory, computes SHA256 hashes, and sends them to the sec-scan API for analysis.

## Architecture
- Single static binary, no runtime dependencies
- Target platforms: macOS (arm64/amd64), Linux (amd64/arm64), Windows (amd64)
- Module path: `github.com/sec-scan-ai/client`

## Client-Server Protocol
1. `GET /api/frameworks/{name}` -> default excludes for the framework (cached locally 24h)
2. `POST /api/files/lookup` -> cached results + unknown checksums (batched at 500)
3. `POST /api/files/analyze` -> analysis results (1 file per request, `--batch-size` controls concurrency)
4. Auth: `Authorization: Bearer sc_<base64>` header
5. `--force` skips lookup, sends all files for re-analysis

## Key Design Decisions
- Framework detection prefers `composer.lock` (exact versions) over `composer.json` (version constraints), walks up from scan dir only (no walk-down)
- Server provides default exclude dirs per framework (cache dirs, compiled templates) - fetched once and cached 24h in `~/.sec-scan/framework-cache.json`
- `vendor/` is never in default excludes - plugins/extensions installed via Composer must be scanned
- Excludes match relative paths from scan root (not directory names globally) - security choice to prevent attackers hiding webshells in known-excluded directory names
- Symlinks followed by default with inode-based loop detection (`--no-follow-symlinks` to disable)
- Graceful Ctrl+C: stops dispatching new requests, waits for in-flight ones, shows partial results
- Auto-cancels on 401 (auth failure) and 429 (rate limit) to avoid wasting requests
- Per-request context timeouts (not shared http.Client.Timeout) for concurrency safety
- First-run setup creates `~/.sec-scan/` and prompts for API token
- `SEC_SCAN_SERVER` env var exists for internal/dev use but is undocumented - default is always `https://sec-scan.ai`
- Ignore file (`~/.sec-scan/ignore`) must never be inside the scan directory - security risk (attacker could plant one to suppress webshell detection)

## Test Files (`test-files/`)
- `clean.php` - no vulnerabilities (should be flagged clean)
- `vulnerable.php` - SQL injection (should be flagged insecure)
- `webshell.php` - backdoor (should be flagged critical)

Quick smoke test: `./sec-scan test-files/`

## Style
- **Never use em-dashes**. Always use a regular hyphen/dash (-) instead. This applies to all code, copy, comments, and documentation.

## Release Workflow
- **Never create releases on your own** - only when the user explicitly asks for one
- To see what changed since the last release: `git log <last-tag>..HEAD --oneline` and `git diff <last-tag>..HEAD`
- Write a new `## vX.Y.Z` section at the top of `CHANGELOG.md` summarizing those changes
- Commit, tag (`vX.Y.Z`), push - the CI workflow extracts the latest section from `CHANGELOG.md` and uses it as the GitHub release body automatically
- `CHANGELOG.md` is the single source of truth for release notes - no separate file to keep in sync

## Testing
- Build: `make build` / Test: `make test` / Cross-compile: `make all`
- `cmd/root_test.go` uses a mock HTTP server (`httptest.NewServer`) for integration tests - any changes to the API client or endpoints require updating the mock server handlers there
- Smoke test: `./sec-scan test-files/` (requires API to be running)
- Dry run test: `./sec-scan --dry-run test-files/` (requires token but does not analyze)
