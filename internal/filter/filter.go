package filter

import (
	"fmt"
	"regexp"
	"strings"
)

const placeholder = "***REDACTED***"

// Match describes a single credential redaction in a file.
type Match struct {
	Line    int    // 1-based line number
	Pattern string // name of the pattern that matched
	Before  string // original matched text (trimmed to context)
	After   string // redacted replacement
}

// pattern is a named compiled regex for credential detection.
type pattern struct {
	name string
	re   *regexp.Regexp
	// replaceFunc builds the replacement string for a match.
	// If nil, the entire match is replaced with the placeholder.
	replaceFunc func(match []string) string
}

// credVarNames matches PHP variable names that typically hold credentials.
// Note: "token" and "key" alone are too generic (match Smarty compiler tokens,
// array keys, etc.), so only qualified forms like auth_token, api_key are included.
var credVarNames = `password|passwd|pwd|secret|api_?key|apikey|` +
	`access_?token|auth_?token|client_?secret|` +
	`private_?key|secret_?key|encryption_?key|` +
	`db_?pass(?:word)?|database_?pass(?:word)?|` +
	`mysql_?pass(?:word)?|smtp_?pass(?:word)?|` +
	`ftp_?pass(?:word)?|ssh_?pass(?:word)?|` +
	`app_?secret|app_?key|jwt_?(?:secret|token|key)|` +
	`auth_?key|session_?(?:token|key|secret)`

// credArrayKeys matches PHP array keys that typically hold credentials.
// "key" and "token" alone are excluded - they cause false positives on
// translation arrays ('PASSWORD' => 'Passwort'), RPC type definitions
// ('Password' => 'string'), and data mappings ('key' => 'column_name').
var credArrayKeys = `password|passwd|pwd|secret|api_?key|apikey|` +
	`access_?token|auth_?token|client_?secret|` +
	`private_?key|secret_?key|encryption_?key|` +
	`db_?pass(?:word)?|database_?pass(?:word)?|` +
	`app_?secret|app_?key|jwt_?(?:secret|token|key)|` +
	`auth_?key|session_?(?:token|key|secret)`

// credDefineNames matches PHP define() constant names that hold credentials.
var credDefineNames = `DB_PASSWORD|DB_PASS|DB_USER|` +
	`AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|` +
	`AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT|` +
	`AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|` +
	`API_KEY|API_SECRET|APP_KEY|APP_SECRET|SECRET_KEY|` +
	`ENCRYPTION_KEY|JWT_SECRET|TOKEN_SECRET|` +
	`SMTP_PASSWORD|FTP_PASSWORD|SSH_PASSWORD|` +
	`[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL)`

// Filter redacts credentials from source code before hashing and sending to the API.
// This ensures: (1) no credentials are sent to the analysis server, and
// (2) files with identical code but different credentials produce the same hash.
type Filter struct {
	patterns []pattern
}

// New creates a Filter with the default credential detection patterns.
// Patterns are inspired by the cc-filter project (github.com/wissem/cc-filter).
func New() *Filter {
	f := &Filter{}

	// Helper: build two patterns (single-quoted and double-quoted) for a given
	// prefix regex. Go's regexp doesn't support backreferences, so we use
	// alternation with separate quote-specific patterns instead.
	// minLen sets the minimum value length to avoid false positives on short
	// values like type names ('string'), translations ('Passwort'), or
	// operators ('==').
	addQuoted := func(name, prefixRe string, minLen int) {
		// Double-quoted variant
		f.patterns = append(f.patterns, pattern{
			name: name,
			re:   regexp.MustCompile(`(?i)(` + prefixRe + `")([^"]+)(")`),
			replaceFunc: func(m []string) string {
				if len(m[2]) < minLen {
					return m[0]
				}
				return m[1] + placeholder + m[3]
			},
		})
		// Single-quoted variant
		f.patterns = append(f.patterns, pattern{
			name: name,
			re:   regexp.MustCompile(`(?i)(` + prefixRe + `')([^']+)(')`),
			replaceFunc: func(m []string) string {
				if len(m[2]) < minLen {
					return m[0]
				}
				return m[1] + placeholder + m[3]
			},
		})
	}

	// PHP variable assignments: $password = "secret"
	// Min 8 chars: avoids operators ('=='), booleans ('true'), short literals
	addQuoted("php_credential_assignment",
		`\$(?:`+credVarNames+`)\s*=\s*`, 8)

	// PHP array/config: 'password' => 'value'
	// Min 12 chars: avoids type names ('string'), translations ('Passwort'),
	// form labels ('password'), and other short non-credential values
	addQuoted("php_array_credential",
		`['"](?:`+credArrayKeys+`)['"]\s*=>\s*`, 12)

	// define() constants: define('DB_PASSWORD', 'secret')
	// Min 8 chars for consistency
	addQuoted("php_define_credential",
		`define\s*\(\s*['"](?:`+credDefineNames+`)['"]\s*,\s*`, 8)

	// getenv/env() with default value: env('SECRET_KEY', 'default')
	// Min 8 chars for consistency
	addQuoted("php_env_default",
		`(?:getenv|env)\s*\(\s*['"](?:[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL|AUTH))['"]\s*,\s*`, 8)

	// Generic API key patterns (high-entropy strings assigned to key-like vars)
	f.patterns = append(f.patterns, pattern{
		name: "api_key_pattern",
		re:   regexp.MustCompile(`(?i)((?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['"]?)([a-zA-Z0-9_\-]{20,})(['"]?)`),
		replaceFunc: func(m []string) string {
			return m[1] + placeholder + m[3]
		},
	})

	// Well-known service token formats
	f.patterns = append(f.patterns,
		pattern{name: "openai_key", re: regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`)},
		pattern{name: "stripe_key", re: regexp.MustCompile(`(?:sk|pk|rk)_(?:test|live)_[a-zA-Z0-9]{20,}`)},
		pattern{name: "slack_token", re: regexp.MustCompile(`xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+`)},
		pattern{name: "github_token", re: regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`)},
		pattern{name: "aws_access_key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	)

	// Bearer tokens in strings
	f.patterns = append(f.patterns, pattern{
		name: "bearer_token",
		re:   regexp.MustCompile(`(?i)(Bearer\s+)[a-zA-Z0-9_\-.]{20,}`),
		replaceFunc: func(m []string) string {
			return m[1] + placeholder
		},
	})

	// Database connection URLs with embedded credentials
	f.patterns = append(f.patterns, pattern{
		name: "database_url",
		re:   regexp.MustCompile(`((?:mysql|pgsql|postgres|mysqli|mongodb|redis|sqlite)://[^:]+:)([^@\s'"]+)(@)`),
		replaceFunc: func(m []string) string {
			return m[1] + placeholder + m[3]
		},
	})

	// PEM private key blocks
	f.patterns = append(f.patterns, pattern{
		name: "private_key_block",
		re:   regexp.MustCompile(`(?s)(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----).+?(-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)`),
		replaceFunc: func(m []string) string {
			return m[1] + "\n" + placeholder + "\n" + m[2]
		},
	})

	return f
}

// Redact replaces credentials in content with placeholders.
// Returns the redacted content and a list of matches describing what was changed.
func (f *Filter) Redact(content string) (string, []Match) {
	var matches []Match
	result := content

	for _, p := range f.patterns {
		if p.replaceFunc != nil {
			result = p.re.ReplaceAllStringFunc(result, func(s string) string {
				submatch := p.re.FindStringSubmatch(s)
				if submatch == nil {
					return s
				}
				replaced := p.replaceFunc(submatch)
				if replaced != s {
					lineNum := lineOf(content, strings.Index(content, s))
					matches = append(matches, Match{
						Line:    lineNum,
						Pattern: p.name,
						Before:  truncate(s, 80),
						After:   truncate(replaced, 80),
					})
				}
				return replaced
			})
		} else {
			result = p.re.ReplaceAllStringFunc(result, func(s string) string {
				lineNum := lineOf(content, strings.Index(content, s))
				matches = append(matches, Match{
					Line:    lineNum,
					Pattern: p.name,
					Before:  truncate(s, 80),
					After:   placeholder,
				})
				return placeholder
			})
		}
	}

	return result, matches
}

// RedactString applies redaction and returns only the redacted content.
// Suitable for use as a content transform function.
func (f *Filter) RedactString(content string) string {
	result, _ := f.Redact(content)
	return result
}

// Summary returns a human-readable summary of redactions for a file.
// Only call this for files that have matches (caller should skip empty ones).
func Summary(path string, matches []Match) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s (%d redaction(s))\n", path, len(matches))
	for _, m := range matches {
		fmt.Fprintf(&b, "    line %-4d  %-30s  %s\n", m.Line, m.Pattern, m.Before)
	}
	b.WriteString("\n")
	return b.String()
}

// lineOf returns the 1-based line number for a byte offset in content.
func lineOf(content string, offset int) int {
	if offset < 0 || offset >= len(content) {
		return 0
	}
	return strings.Count(content[:offset], "\n") + 1
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
