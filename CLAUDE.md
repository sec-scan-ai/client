# sec-scan Client

> **About this file:** CLAUDE.md is for agent guidance - architectural decisions, rules, conventions, and gotchas that can't be inferred from reading code. Focus on the "why", not the "what".

## Overview
Go CLI client for the sec-scan.ai PHP security scanner. Collects PHP files from a directory, computes SHA256 hashes, and sends them to the sec-scan API for analysis.

## Architecture
- Single static binary, no runtime dependencies
- Target platforms: macOS (arm64/amd64), Linux (amd64/arm64), Windows (amd64)
- Module path: `github.com/sec-scan-ai/client`

## Client-Server Protocol
1. `POST /api/files/lookup` - `{checksums: [...]}` -> `{results: {hash: {secure, risk, details}}, unknown: [...]}`
2. `POST /api/files/analyze` - `{files: [{checksum, path, size, content}...], framework: "..."}` -> `{results: {...}}`
3. Auth: `Authorization: Bearer sc_<base64>` header
4. Analyze sends 1 file per request, `--batch-size` controls parallel concurrency
5. Lookup batched at 500 checksums per request
6. `--force` skips lookup, sends all files for re-analysis

## Key Design Decisions
- Excludes match relative paths from scan root (not directory names globally) - security choice to prevent attackers hiding webshells in known-excluded directory names
- Symlinks followed by default with inode-based loop detection (`--no-follow-symlinks` to disable)
- Graceful Ctrl+C: stops dispatching new requests, waits for in-flight ones, shows partial results
- Auto-cancels on 401 (auth failure) and 429 (rate limit) to avoid wasting requests
- Per-request context timeouts (not shared http.Client.Timeout) for concurrency safety
- First-run setup creates `~/.sec-scan/` and prompts for API token

## Test Files (`test-files/`)
- `clean.php` - no vulnerabilities (should be flagged clean)
- `vulnerable.php` - SQL injection (should be flagged insecure)
- `webshell.php` - backdoor (should be flagged critical)

Quick smoke test: `./sec-scan test-files/`

## Style
- **Never use em-dashes**. Always use a regular hyphen/dash (-) instead. This applies to all code, copy, comments, and documentation.

## Development Notes
- The sec-scan API must be running for the client to work.
- Build: `make build` / Test: `make test` / Cross-compile: `make all`
