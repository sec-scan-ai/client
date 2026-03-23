# Changelog

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
