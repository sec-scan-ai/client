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
6. `--rescan` runs lookup, then re-analyzes files matching specified statuses (e.g. `--rescan critical,high,warning`) - mutually exclusive with `--force`

### Analysis result statuses
The server returns a `secure` field per file with one of these values:
- `"yes"` - file is clean
- `"no"` - file is insecure, `risk` field contains severity (low/medium/high/critical), `details` has explanation
- `"warning"` - file cannot be classified as clean or insecure (e.g. ionCube encrypted), `details` has explanation
- `"error"` - analysis failed, `details` has reason

### Exit code logic
Two independent controls determine exit code 1:
- `--fail-on` (default: `low`) - minimum risk level for insecure files
- `--fail-on-warning` (default: `true`) - whether warnings cause failure independently

These are separate because warnings (unanalyzable files) are a different concern than insecure findings - a warning could be hiding anything, including critical vulnerabilities.

## Credential Redaction
- Enabled by default (`--no-redact` to disable) - credentials are replaced with `***REDACTED***` before hashing and before sending content to the API
- Applied at two points: during file collection (before SHA256 checksum) and during content read (before API submission) - both use the same `ContentFilter` function to ensure consistency
- Patterns are PHP-focused: `$password = "..."`, `'key' => '...'`, `define('SECRET', '...')`, plus well-known token formats (OpenAI, Stripe, GitHub, AWS, Slack, Bearer, database URLs, PEM blocks)
- Inspired by github.com/wissem/cc-filter but reimplemented as a focused Go package (`internal/filter/`) since we only need content redaction, not cc-filter's hook system
- `--redact-dry-run` reads files, applies the filter, and shows what would be redacted per file - exits before any API calls, useful for verifying filter coverage on a new codebase
- The filter preserves code structure (variable names, quotes, operators) and only replaces values, so security analysis accuracy is not affected

## Self-Update
- `sec-scan update` checks the latest GitHub release via the GitHub API (`/repos/sec-scan-ai/client/releases/latest`)
- Downloads the matching binary for the current OS/architecture (same naming convention as release assets: `sec-scan-{os}-{arch}`)
- Replaces the current executable using atomic rename (old -> .old, new -> current, remove .old)
- If the rename fails (permission denied), the old binary is restored and the user is told to try sudo
- Version comparison is simple string equality on the tag name (no semver parsing needed)
- No external dependencies, uses only stdlib `net/http` and `encoding/json`

## Key Design Decisions
- Framework detection prefers `composer.lock` (exact versions) over `composer.json` (version constraints), walks up from scan dir only (no walk-down)
- Magento is split into Magento 1 and Magento 2 - detection checks for M2-specific packages (`magento/framework`, `magento/product-community-edition`, `magento/product-enterprise-edition`)
- Server provides default exclude dirs per framework (cache dirs, compiled templates) - fetched once and cached 24h in `~/.sec-scan/framework-cache.json`
- `vendor/` is never in default excludes - plugins/extensions installed via Composer must be scanned
- Excludes match relative paths from scan root (not directory names globally) - security choice to prevent attackers hiding webshells in known-excluded directory names
- Symlinks followed by default with inode-based loop detection (`--no-follow-symlinks` to disable)
- Graceful Ctrl+C: stops dispatching new requests, waits for in-flight ones, shows partial results
- Auto-cancels on 401 (auth failure) and 429 (rate limit) to avoid wasting requests
- Per-request context timeouts (not shared http.Client.Timeout) for concurrency safety
- First-run setup creates `~/.sec-scan/` and prompts for API token
- Ignore file (`~/.sec-scan/ignore`) must never be inside the scan directory - security risk (attacker could plant one to suppress webshell detection)
- Large files (>400KB) are split into overlapping 400KB chunks (20KB overlap) - prevents attackers from hiding malicious code beyond a truncation point. Each chunk is analyzed independently and appears as a separate entry with a `[1/3]` suffix. No merging of results.
- `--rescan` does lookup first (unlike `--force`) so only matching files are re-sent - useful for re-checking high-risk findings or warnings without burning API credits on the entire codebase. Sends `force: true` to the server so it actually re-analyzes rather than returning cached results. Has no effect with `--dry-run` (dry-run exits before lookup).

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

### macOS code signing and notarization
- Uses [quill](https://github.com/anchore/quill) (from Anchore) to sign and notarize macOS binaries on Linux, no macOS runner needed
- All binaries (all platforms) are built in a single job on `ubuntu-latest`
- After building, quill runs `sign-and-notarize` on each darwin binary
- Required GitHub repository secrets (same naming convention as the sesaam CLI):
  - `APPLE_DEVELOPER_CERTIFICATE_P12_BASE64` - Developer ID Application `.p12` certificate, base64-encoded
  - `APPLE_DEVELOPER_CERTIFICATE_PASSWORD` - password for the `.p12`
  - `APPLE_NOTARIZE_KEY_P8_BASE64` - App Store Connect API key (`.p8`), base64-encoded
  - `APPLE_NOTARIZE_KEY_ID` - App Store Connect API key ID
  - `APPLE_NOTARIZE_KEY_ISSUER` - App Store Connect API issuer ID
- Quill reads these via environment variables: `QUILL_SIGN_P12`, `QUILL_SIGN_PASSWORD`, `QUILL_NOTARY_KEY`, `QUILL_NOTARY_KEY_ID`, `QUILL_NOTARY_ISSUER`
- The install script clears the quarantine xattr after download so notarized binaries run without prompts

## Documentation
- When adding new CLI flags or features, always update `README.md` (usage examples in Usage section + row in Options table) in addition to `CLAUDE.md`

## Testing
- Build: `make build` / Test: `make test` / Cross-compile: `make all`
- `cmd/root_test.go` uses a mock HTTP server (`httptest.NewServer`) for integration tests - any changes to the API client or endpoints require updating the mock server handlers there
- Smoke test: `./sec-scan test-files/` (requires API to be running)
- Dry run test: `./sec-scan --dry-run test-files/` (requires token but does not analyze)
