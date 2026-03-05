# Changelog

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
