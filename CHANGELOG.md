# Changelog

## v0.8.1

### Fix: live risk counter missed cache-hit findings

The "Analyzing [N/M, X critical, ...]" progress line and the final summary's risk suffix now include insecure/warning findings resolved from the lookup cache, not just freshly-analyzed files. Previously, a scan where most files came back from cache would show a much lower in-progress count than the final report. The final `BuildSummary` was already correct - only the live display was off.

## v0.8.0

### Daily auto-update

sec-scan now quietly keeps itself up to date. Once per day (on a normal invocation) it does a conditional GET against the GitHub releases API, and if a newer release exists it downloads the binary, verifies it against `checksums.txt`, and atomically replaces `~/.sec-scan/bin/sec-scan`. The currently running command keeps using its in-memory binary; the next invocation transparently picks up the new version. All failures are silent. Set `SEC_SCAN_NO_UPDATE_CHECK=1` (or `CI=true`) to disable. Integrity verification is mandatory - releases without `checksums.txt` will not be installed automatically.

New installs via `install.sh` place the real binary at `~/.sec-scan/bin/sec-scan` with a symlink at `/usr/local/bin/sec-scan` (user-owned, so updates run unprivileged). `sec-scan update` silently migrates legacy plain-file installs to this layout on first run.

### Fix: credential filter reported wrong line numbers

`--redact-dry-run` now reports the correct line for every credential occurrence. Previously, when the same credential text appeared on multiple lines, every match reported the first line's number. Users fixing the reported line would miss later copies.

### Framework detection boundary

Detection now stops walking up the directory tree at `$HOME` when scanning inside home. Prevents a composer.json planted in a parent directory (e.g. `$HOME/composer.json`, `/tmp/composer.json`) from influencing the framework hint sent to the server.

### Supply chain hardening

The release workflow now pins all GitHub Actions to commit SHAs instead of mutable tags, and pins the `quill` installer to a specific release tag rather than `main`. Closes a class of attack where a compromised upstream repo could inject code into our release pipeline with access to Apple signing secrets.

### Other

- Update check writes its cache timestamp even on API errors (rate limit, network failure), closing a retry loop where a transient GitHub outage would cause every subsequent run to re-attempt the API call.
- `sec-scan update`'s sudo invocation now uses absolute `/usr/bin/sudo` and `/bin/ln` paths and prints the "why" before triggering the sudo prompt.
- `Makefile` ldflags typo fixed - `make build` now produces binaries with the correct version string (previously silently fell back to "dev").
- Ignore-file warnings now respect `--quiet`.
- New `CI` workflow runs `go vet`, tests, and a `make build` version-string check on every push/PR.

## v0.7.3

### Sylius detection

Sylius shops are now correctly identified, split into `Sylius 1.x` and `Sylius 2.x` based on the `sylius/sylius` package version. Previously these installs were misidentified as `Symfony` because Sylius depends on `symfony/framework-bundle`, which was matched first. The Sylius monorepo (source checkout) is also detected via the composer.json `name` field, matching how Shopware monorepos are handled.

## v0.7.2

### Fix Shopware 6 monorepo detected as Shopware 5

When scanning the Shopware 6 source repository (or a development checkout), the framework was incorrectly identified as Shopware 5. This happened because the monorepo's composer.json doesn't require `shopware/core` or `shopware/platform` as dependencies - it *is* those packages. The detection now also checks the composer.json `name` field, so projects named `shopware/platform` or `shopware/core` are correctly identified as Shopware 6.

## v0.7.1

### Fix single-file scan showing "." as filename

When scanning a single file (e.g. `sec-scan file.php`), the filename was displayed as "." in results because the file path was used as its own base directory for relative path computation. Now uses the file's parent directory as the base, so the filename is shown correctly.

## v0.7.0

### Scan duration and cache stats in summary

The summary output now shows how long the scan took and how many files were resolved from cache vs analyzed. This gives visibility into cache effectiveness and scan performance.

Text output shows cached count with a hit percentage, analyzed count, and duration in seconds. In force mode (where everything is re-analyzed), the cached line is omitted. JSON output includes `cached`, `analyzed`, and `duration` fields in the summary object.

## v0.6.0

### Credential redaction

File content is now redacted before hashing and sending to the API. Passwords, API keys, tokens, database URLs, PEM private keys, and other credentials are replaced with `***REDACTED***` placeholders. This means no secrets leave your machine, and files with identical code but different credentials (e.g. staging vs production configs) produce the same hash, avoiding duplicate analysis.

Redaction is on by default. Use `--no-redact` to disable, or `--redact-dry-run` to preview what would be redacted without sending anything.

```bash
# Preview redactions
sec-scan /path/to/project --redact-dry-run

# Disable redaction (not recommended)
sec-scan /path/to/project --no-redact
```

### Self-update

The CLI can now update itself to the latest GitHub release:

```bash
sec-scan update
```

Downloads the correct binary for your OS/architecture and replaces the current executable. Only updates when a newer version is available (proper semver comparison).

### macOS code signing and notarization

macOS binaries are now signed with a Developer ID certificate and notarized by Apple using [quill](https://github.com/anchore/quill). No more Gatekeeper warnings on first run.

## v0.5.0

### Selective rescan by status

New `--rescan` flag to re-analyze only files matching specific statuses from a previous scan. Unlike `--force` which skips the cache entirely, `--rescan` performs a lookup first and only re-sends files that match the specified statuses - saving API credits when you only need to re-check certain findings.

```bash
# Re-analyze only critical/high findings and warnings
sec-scan /path/to/project --rescan critical,high,warning

# Re-analyze all warnings (e.g. after updating the analyzer)
sec-scan /path/to/project --rescan warning
```

Accepted values: `low`, `medium`, `high`, `critical`, `warning`, `error` (comma-separated). Also configurable via `SEC_SCAN_RESCAN` env var. Mutually exclusive with `--force`.

## v0.4.0

### Warning status for unanalyzable files

Files that cannot be classified as clean or insecure (e.g. ionCube or Zend Guard encrypted files) are now reported as warnings instead of being silently skipped. Warnings are shown in both text and JSON output with their own counter in the summary.

Warnings cause exit code 1 by default. Use `--fail-on-warning=false` to treat them as informational. This is a separate control from `--fail-on`, which only applies to insecure file risk levels - because an unanalyzable file could be hiding anything.

### Magento 1/2 detection

Framework detection now distinguishes Magento 1 and Magento 2. Magento 2 is identified by the presence of `magento/framework`, `magento/product-community-edition`, or `magento/product-enterprise-edition` in composer. Any other `magento/` package without these is detected as Magento 1.

## v0.3.3

### Chunked analysis for large files

Files over 400KB are now split into overlapping 400KB chunks (with 20KB overlap) and each chunk is analyzed independently. Previously, files over 500KB were truncated before analysis - an attacker could pad a webshell with junk at the top to hide malicious code beyond the truncation point. Chunking eliminates this blind spot and also fixes checksum mismatches caused by truncation.

Chunks appear as separate entries in output with a `[1/3]` suffix. The overlap ensures malicious code at chunk boundaries is fully contained in at least one chunk.

## v0.3.2

### New: Ignore list for false positives

Files flagged as insecure can now be ignored by adding their SHA256 checksum to `~/.sec-scan/ignore`. Ignored files are skipped entirely - no lookup or analysis requests are sent. Use `--ignore-file` to specify a custom path.

For security, the ignore file must not be inside the scan directory - an attacker could plant one to suppress detection of their webshell.

### Live risk counters during analysis

The progress spinner now shows risk level counts as results come back from the server, so you can see findings in real-time without waiting for the full scan to finish.

## v0.3.1

### New: `--dry-run` flag

Shows what would be scanned without sending files to the server - useful for debugging framework detection, verifying excludes, and checking file counts before running a full scan.

### Improved test coverage

Added integration tests for the full scan flow using a mock HTTP server, covering successful scans, cached files, force mode, auth/rate-limit errors, JSON output, and fail-on thresholds. Also added render tests for text and JSON output formatting.

## v0.3.0

### Smarter framework detection

- **composer.lock preferred over composer.json** - Uses exact installed versions instead of version constraints for more reliable detection (e.g. correctly distinguishing Shopware 5 vs 6, OXID 6.x vs 7.x).
- **New frameworks** - Added detection for JTL-Shop 5, PrestaShop, and Sylius.
- **Removed walk-down search** - Previously the client searched subdirectories for `composer.json` which could pick the wrong project in multi-project directories. Now only checks the scan directory and walks up to parent directories.

### Server-driven default excludes

The client now fetches default exclude directories from the server after detecting the framework. This automatically skips directories containing auto-generated PHP files (compiled templates, framework caches, generated proxy classes) that would produce false positives.

- Default excludes are shown in the progress output
- Cached locally for 24 hours (`~/.sec-scan/framework-cache.json`)
- Use `--no-default-excludes` to skip server-provided defaults
- User `--exclude` flags are always additive on top of defaults

### Fix: Linux binary compatibility

Linux binaries are now fully static. Previously, they were dynamically linked against glibc and failed on older distributions.

## v0.2.0

### Fix: scanning files with embedded binary data

PHP files containing invalid UTF-8 bytes (e.g. adminer, minified/packed files) previously failed with a "Checksum mismatch" error. Both `FileChecksum` and `ReadContent` now sanitize invalid UTF-8 before processing.

## v0.1.1

Initial public release with install script.

## v0.1.0

First commit.
