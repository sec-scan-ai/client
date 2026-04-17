package filter

import (
	"strings"
	"testing"
)

func TestRedact_PHPVariableAssignment(t *testing.T) {
	f := New()

	tests := []struct {
		name    string
		input   string
		want    string
		matches int
	}{
		{
			name:    "simple password",
			input:   `$password = "secret12345";`,
			want:    `$password = "` + placeholder + `";`,
			matches: 1,
		},
		{
			name:    "single quotes",
			input:   `$api_key = 'sk_live_abc123def456';`,
			want:    `$api_key = '` + placeholder + `';`,
			matches: 1,
		},
		{
			name:    "apiKey camelCase",
			input:   `$apiKey = "mySecretApiKey123";`,
			want:    `$apiKey = "` + placeholder + `";`,
			matches: 1,
		},
		{
			name:    "db_password",
			input:   `$db_password = "root_pass_123";`,
			want:    `$db_password = "` + placeholder + `";`,
			matches: 1,
		},
		{
			name:    "no credential - normal variable",
			input:   `$name = "John";`,
			want:    `$name = "John";`,
			matches: 0,
		},
		{
			name:    "secret_key with spaces",
			input:   `$secret_key  =  "abc123def456ghi789jkl";`,
			want:    `$secret_key  =  "` + placeholder + `";`,
			matches: 1,
		},
		{
			name:    "short value not redacted",
			input:   `$token = "==";`,
			want:    `$token = "==";`,
			matches: 0,
		},
		{
			name:    "generic token variable not matched",
			input:   `$token = "some_long_value_here";`,
			want:    `$token = "some_long_value_here";`,
			matches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matches := f.Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact() =\n  %s\nwant:\n  %s", got, tt.want)
			}
			if len(matches) != tt.matches {
				t.Errorf("Redact() matches = %d, want %d", len(matches), tt.matches)
			}
		})
	}
}

func TestRedact_PHPArrayCredential(t *testing.T) {
	f := New()

	input := `$config = [
    'password' => 'db_secret_123_value',
    'host' => 'localhost',
    'api_key' => 'key_abc_def_ghi_long',
];`

	got, matches := f.Redact(input)

	if strings.Contains(got, "db_secret_123_value") {
		t.Error("password value should be redacted")
	}
	if strings.Contains(got, "key_abc_def_ghi_long") {
		t.Error("api_key value should be redacted")
	}
	if !strings.Contains(got, "'host' => 'localhost'") {
		t.Error("non-credential value should be preserved")
	}
	if !strings.Contains(got, "'password' => '"+placeholder+"'") {
		t.Errorf("expected password redaction, got:\n%s", got)
	}
	if len(matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(matches))
	}
}

func TestRedact_PHPArrayCredential_ShortValueNotRedacted(t *testing.T) {
	f := New()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "type definition",
			input: `'Password' => 'string'`,
		},
		{
			name:  "translation",
			input: `'PASSWORD' => 'Passwort'`,
		},
		{
			name:  "form label",
			input: `'password' => 'password'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matches := f.Redact(tt.input)
			if got != tt.input {
				t.Errorf("short value should not be redacted:\n  input: %s\n  got:   %s", tt.input, got)
			}
			if len(matches) != 0 {
				t.Errorf("expected 0 matches, got %d", len(matches))
			}
		})
	}
}

func TestRedact_GenericKeyTokenNotMatched(t *testing.T) {
	f := New()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "generic key array",
			input: `"key" => "oxarticles.OXTITLE"`,
		},
		{
			name:  "generic token array",
			input: `'Token' => 'string'`,
		},
		{
			name:  "data mapping",
			input: `"key" => "oxarticles.OXSEARCHKEYS"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matches := f.Redact(tt.input)
			if got != tt.input {
				t.Errorf("generic key/token should not be redacted:\n  input: %s\n  got:   %s", tt.input, got)
			}
			if len(matches) != 0 {
				t.Errorf("expected 0 matches, got %d", len(matches))
			}
		})
	}
}

func TestRedact_PHPDefine(t *testing.T) {
	f := New()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "WordPress DB_PASSWORD",
			input: `define('DB_PASSWORD', 'wp_secret_pass');`,
			want:  `define('DB_PASSWORD', '` + placeholder + `');`,
		},
		{
			name:  "WordPress AUTH_KEY",
			input: `define('AUTH_KEY', 'put your unique phrase here');`,
			want:  `define('AUTH_KEY', '` + placeholder + `');`,
		},
		{
			name:  "custom SECRET_KEY",
			input: `define("APP_SECRET", "s3cr3t_v4lu3");`,
			want:  `define("APP_SECRET", "` + placeholder + `");`,
		},
		{
			name:  "non-credential define preserved",
			input: `define('DB_HOST', 'localhost');`,
			want:  `define('DB_HOST', 'localhost');`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := f.Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact() =\n  %s\nwant:\n  %s", got, tt.want)
			}
		})
	}
}

func TestRedact_ServiceTokens(t *testing.T) {
	f := New()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "OpenAI key",
			input: `$key = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD";`,
		},
		{
			name:  "Stripe key",
			input: `sk_test_abcdefghijklmnopqrstuvwxyz`,
		},
		{
			name:  "GitHub token",
			input: `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matches := f.Redact(tt.input)
			if len(matches) == 0 {
				t.Errorf("expected match for %s, got none", tt.name)
			}
			if got == tt.input {
				t.Errorf("expected redaction for %s", tt.name)
			}
		})
	}
}

func TestRedact_DatabaseURL(t *testing.T) {
	f := New()

	input := `$dsn = "mysql://admin:s3cr3t_pass@localhost:3306/mydb";`
	got, matches := f.Redact(input)

	if strings.Contains(got, "s3cr3t_pass") {
		t.Error("database password should be redacted")
	}
	if !strings.Contains(got, "mysql://admin:"+placeholder+"@localhost") {
		t.Errorf("expected database URL redaction, got:\n%s", got)
	}
	if len(matches) == 0 {
		t.Error("expected at least 1 match")
	}
}

func TestRedact_BearerToken(t *testing.T) {
	f := New()

	input := `$headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"];`
	got, matches := f.Redact(input)

	if strings.Contains(got, "eyJhbGciOi") {
		t.Error("bearer token should be redacted")
	}
	if !strings.Contains(got, "Bearer "+placeholder) {
		t.Errorf("expected bearer redaction, got:\n%s", got)
	}
	if len(matches) == 0 {
		t.Error("expected at least 1 match")
	}
}

func TestRedact_PrivateKeyBlock(t *testing.T) {
	f := New()

	input := `$key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoKPN
-----END RSA PRIVATE KEY-----";`

	got, matches := f.Redact(input)

	if strings.Contains(got, "MIIEpAIBAAK") {
		t.Error("private key content should be redacted")
	}
	if !strings.Contains(got, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("PEM header should be preserved")
	}
	if !strings.Contains(got, "-----END RSA PRIVATE KEY-----") {
		t.Error("PEM footer should be preserved")
	}
	if len(matches) == 0 {
		t.Error("expected at least 1 match")
	}
}

func TestRedact_PreservesNonCredentialCode(t *testing.T) {
	f := New()

	input := `<?php
namespace App\Controller;

class UserController {
    public function index() {
        $users = $this->repository->findAll();
        $count = count($users);
        echo "Found $count users";
        return $users;
    }
}`

	got, matches := f.Redact(input)

	if got != input {
		t.Errorf("non-credential code should not be modified, got:\n%s", got)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for clean code, got %d", len(matches))
	}
}

func TestRedact_MultipleCredentialsInFile(t *testing.T) {
	f := New()

	input := `<?php
$db_password = "secret123_long";
$api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
define('AUTH_KEY', 'wp_salt_value_here_long');
$dsn = "mysql://root:rootpass_long@localhost/db";
$name = "John";
`

	got, matches := f.Redact(input)

	if strings.Contains(got, "secret123_long") {
		t.Error("db_password should be redacted")
	}
	if strings.Contains(got, "rootpass_long") {
		t.Error("database URL password should be redacted")
	}
	if !strings.Contains(got, `$name = "John"`) {
		t.Error("non-credential variable should be preserved")
	}
	if len(matches) < 3 {
		t.Errorf("expected at least 3 matches, got %d", len(matches))
	}
}

func TestRedact_SameCodeDifferentCredentials(t *testing.T) {
	f := New()

	code1 := `<?php
$password = "production_secret_abc_long";
echo "Hello World";
`
	code2 := `<?php
$password = "staging_secret_xyz_long";
echo "Hello World";
`

	redacted1, _ := f.Redact(code1)
	redacted2, _ := f.Redact(code2)

	if redacted1 != redacted2 {
		t.Errorf("same code with different credentials should produce identical output\ngot1: %s\ngot2: %s", redacted1, redacted2)
	}
}

func TestRedactString(t *testing.T) {
	f := New()
	input := `$password = "long_secret_value";`
	got := f.RedactString(input)
	if strings.Contains(got, "long_secret_value") {
		t.Error("RedactString should redact credentials")
	}
}

func TestSummary(t *testing.T) {
	matches := []Match{
		{Line: 5, Pattern: "php_credential_assignment", Before: `$password = "secret"`},
		{Line: 10, Pattern: "database_url", Before: `mysql://root:pass@localhost`},
	}

	s := Summary("config.php", matches)
	if !strings.Contains(s, "config.php (2 redaction(s))") {
		t.Errorf("expected summary header, got:\n%s", s)
	}
	if !strings.Contains(s, "line 5") {
		t.Error("expected line number in summary")
	}
}

func TestSummary_NoMatches(t *testing.T) {
	s := Summary("clean.php", nil)
	if !strings.Contains(s, "0 redaction(s)") {
		t.Errorf("expected 0 redactions, got: %s", s)
	}
}

func TestRedact_LineNumbersDistinctForRepeatedMatches(t *testing.T) {
	// Regression: strings.Index would return the first occurrence for every
	// repeated match, so duplicate credentials on different lines all got
	// the same (wrong) line number. Each occurrence must report its own line.
	f := New()
	content := `<?php
$password = "secret12345";
// unrelated
$password = "secret12345";
`

	_, matches := f.Redact(content)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("first match line = %d, want 2", matches[0].Line)
	}
	if matches[1].Line != 4 {
		t.Errorf("second match line = %d, want 4", matches[1].Line)
	}
}

func TestRedact_LineNumbersDistinctAcrossManyOccurrences(t *testing.T) {
	f := New()
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 10; i++ {
		b.WriteString(`$api_key = "samekey_abcdefghij";` + "\n")
	}
	_, matches := f.Redact(b.String())

	if len(matches) != 10 {
		t.Fatalf("expected 10 matches, got %d", len(matches))
	}
	seen := make(map[int]bool)
	for _, m := range matches {
		seen[m.Line] = true
	}
	if len(seen) != 10 {
		t.Errorf("expected 10 distinct line numbers, got %d: %+v", len(seen), seen)
	}
}
