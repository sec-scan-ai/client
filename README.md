# sec-scan CLI

Command-line client for [sec-scan.ai](https://sec-scan.ai) - AI-powered PHP security scanning that finds vulnerable code before attackers exploit it.

Malware scanners tell you you've been hacked. sec-scan finds the vulnerable code that let it happen - SQL injection, SSRF, unrestricted uploads, backdoors - so you can fix the cause, not just clean up the mess.

Built with deep knowledge of OXID eShop, Shopware, Magento, and other PHP frameworks to deliver near-zero false positives.

## How it works

1. The CLI collects PHP files from your project and computes SHA256 hashes
2. Known files are resolved instantly from a global cache
3. Unknown files are uploaded to the sec-scan API for analysis
4. Results are displayed with risk levels and details

Every file is cached globally by content hash - re-scans, CI runs, and team sharing return results in milliseconds.

## Installation

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/sec-scan-ai/client/main/install.sh | sh
```

This auto-detects your OS and architecture, downloads the latest binary, and installs it to `/usr/local/bin`.

**Windows:** Download `sec-scan-windows-amd64.exe` from the [releases page](https://github.com/sec-scan-ai/client/releases) and add it to your PATH.

## Setup

On first run, sec-scan will create `~/.sec-scan/` and prompt you for your API token. You can get a token from your account at [sec-scan.ai](https://sec-scan.ai).

Alternatively, configure via environment variables or a `.env` file:

```bash
# ~/.sec-scan/.env or .env in your project
SEC_SCAN_TOKEN=sc_your_token_here
```

## Quick test

The `test-files/` directory contains three PHP files for verifying your setup - a clean file, one with SQL injection, and a webshell:

```bash
sec-scan test-files/
```

You should see one clean file, one high-risk finding, and one critical finding.

## Usage

```bash
# Scan a PHP project
sec-scan /path/to/project

# Scan with explicit token
sec-scan /path/to/project --token sc_your_token

# Exclude directories (paths relative to scan root)
sec-scan /path/to/project --exclude vendor --exclude admin/templates_c

# Force re-analysis of all files (skip cache)
sec-scan /path/to/project --force

# JSON output for CI pipelines
sec-scan /path/to/project --output json

# Fail only on high or critical findings (default: low)
sec-scan /path/to/project --fail-on high

# Quiet mode - only show results, no progress
sec-scan /path/to/project --quiet

# Specify framework explicitly (auto-detected from composer.lock/composer.json by default)
sec-scan /path/to/project --framework "Shopware 6"

# Increase parallelism (default: 10 concurrent requests)
sec-scan /path/to/project --batch-size 20

# Scan a single file
sec-scan /path/to/file.php
```

## Options

| Flag | Short | Env var | Default | Description |
|------|-------|---------|---------|-------------|
| `--token` | `-t` | `SEC_SCAN_TOKEN` | - | API token (required) |
| `--batch-size` | `-b` | `SEC_SCAN_BATCH_SIZE` | `10` | Concurrent analysis requests (max 50) |
| `--exclude` | `-e` | - | - | Directories to exclude, relative to scan root (repeatable) |
| `--framework` | `-f` | `SEC_SCAN_FRAMEWORK` | auto-detect | PHP framework hint |
| `--force` | - | - | `false` | Re-analyze all files, skip cache |
| `--fail-on` | - | `SEC_SCAN_FAIL_ON` | `low` | Minimum risk level for exit code 1 |
| `--quiet` | `-q` | `SEC_SCAN_QUIET` | `false` | Suppress progress output |
| `--output` | `-o` | `SEC_SCAN_OUTPUT` | `text` | Output format: `text` or `json` |
| `--no-follow-symlinks` | - | - | `false` | Do not follow symlinks |
| `--no-default-excludes` | - | - | `false` | Skip server-provided default exclude directories |

Flag values take precedence over environment variables.

## Excludes

Excludes match against **relative paths from the scan root**, not directory names globally. This is a deliberate security choice - an attacker could create a directory named `templates_c` anywhere in your project to hide webshells if excludes matched all occurrences.

```bash
# Only excludes <root>/vendor, NOT <root>/src/vendor
sec-scan /path/to/project --exclude vendor

# Excludes <root>/admin/templates_c specifically
sec-scan /path/to/project --exclude admin/templates_c

# To exclude vendor in multiple locations, list them explicitly
sec-scan /path/to/project --exclude vendor --exclude lib/vendor
```

Excludes are case-insensitive.

### Default excludes

When sec-scan detects a framework, it fetches default exclude directories from the server. These skip auto-generated files (compiled templates, framework caches, generated proxy classes) that would produce false positives. Default excludes are shown in the progress output and cached locally for 24 hours.

User `--exclude` flags are always additive on top of defaults. Use `--no-default-excludes` to disable server-provided defaults.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All files clean (or below `--fail-on` threshold) |
| `1` | Vulnerabilities found at or above `--fail-on` level |

## CI/CD integration

```bash
# Fail the pipeline on high or critical findings
sec-scan /path/to/project --output json --quiet --fail-on high

# Parse JSON output
sec-scan /path/to/project --output json --quiet | jq '.files[] | select(.risk == "critical")'
```

## Risk levels

| Level | Description |
|-------|-------------|
| **critical** | Immediate threat - requires urgent action |
| **high** | Serious vulnerability - should be fixed promptly |
| **medium** | Exploitable under specific conditions |
| **low** | Minor issues, informational |

## Supported frameworks

sec-scan auto-detects frameworks from `composer.lock` (preferred) or `composer.json` and adjusts analysis accordingly:

- OXID eShop 6 / 7
- Shopware 5 / 6
- Magento
- Laravel
- Symfony
- WordPress / WooCommerce
- JTL-Shop 5
- PrestaShop
- Sylius

## License

MIT - see [LICENSE](LICENSE) for details.
