package config

import (
	"os"
	"testing"
)

func TestResolveEnv_Defaults(t *testing.T) {
	clearEnv(t)
	c := &Config{}
	c.ResolveEnv()

	if c.Server != DefaultServer {
		t.Errorf("Server = %q, want %q", c.Server, DefaultServer)
	}
	if c.BatchSize != DefaultBatchSize {
		t.Errorf("BatchSize = %d, want %d", c.BatchSize, DefaultBatchSize)
	}
	if c.FailOn != DefaultFailOn {
		t.Errorf("FailOn = %q, want %q", c.FailOn, DefaultFailOn)
	}
	if c.Output != DefaultOutput {
		t.Errorf("Output = %q, want %q", c.Output, DefaultOutput)
	}
	if c.Quiet {
		t.Error("Quiet should be false by default")
	}
}

func TestResolveEnv_EnvOverridesDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("SEC_SCAN_SERVER", "http://example.com:8080")
	t.Setenv("SEC_SCAN_TOKEN", "sc_test123")
	t.Setenv("SEC_SCAN_BATCH_SIZE", "25")
	t.Setenv("SEC_SCAN_FRAMEWORK", "Shopware 6")
	t.Setenv("SEC_SCAN_FAIL_ON", "high")
	t.Setenv("SEC_SCAN_QUIET", "true")
	t.Setenv("SEC_SCAN_OUTPUT", "json")

	c := &Config{}
	c.ResolveEnv()

	if c.Server != "http://example.com:8080" {
		t.Errorf("Server = %q, want %q", c.Server, "http://example.com:8080")
	}
	if c.Token != "sc_test123" {
		t.Errorf("Token = %q, want %q", c.Token, "sc_test123")
	}
	if c.BatchSize != 25 {
		t.Errorf("BatchSize = %d, want 25", c.BatchSize)
	}
	if c.Framework != "Shopware 6" {
		t.Errorf("Framework = %q, want %q", c.Framework, "Shopware 6")
	}
	if c.FailOn != "high" {
		t.Errorf("FailOn = %q, want %q", c.FailOn, "high")
	}
	if !c.Quiet {
		t.Error("Quiet should be true")
	}
	if c.Output != "json" {
		t.Errorf("Output = %q, want %q", c.Output, "json")
	}
}

func TestResolveEnv_FlagsTakePrecedence(t *testing.T) {
	clearEnv(t)
	t.Setenv("SEC_SCAN_SERVER", "http://env-server.com")
	t.Setenv("SEC_SCAN_TOKEN", "sc_envtoken")
	t.Setenv("SEC_SCAN_BATCH_SIZE", "30")

	c := &Config{
		Server:    "http://flag-server.com",
		Token:     "sc_flagtoken",
		BatchSize: 15,
	}
	c.ResolveEnv()

	if c.Server != "http://flag-server.com" {
		t.Errorf("Server = %q, want flag value", c.Server)
	}
	if c.Token != "sc_flagtoken" {
		t.Errorf("Token = %q, want flag value", c.Token)
	}
	if c.BatchSize != 15 {
		t.Errorf("BatchSize = %d, want flag value 15", c.BatchSize)
	}
}

func TestValidate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name:    "missing token",
			config:  Config{Path: "/tmp", FailOn: "low", Output: "text", BatchSize: 10},
			wantErr: "API token is required",
		},
		{
			name:    "missing path",
			config:  Config{Token: "sc_test", FailOn: "low", Output: "text", BatchSize: 10},
			wantErr: "scan path is required",
		},
		{
			name:   "valid config",
			config: Config{Token: "sc_test", Path: "/tmp", FailOn: "low", Output: "text", BatchSize: 10, Server: "https://sec-scan.ai"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains([]string{err.Error()}, err.Error()) {
					t.Fatalf("error %q does not match expected", err.Error())
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_BatchSizeClamping(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"below min", -5, MinBatchSize},
		{"zero", 0, MinBatchSize},
		{"normal", 10, 10},
		{"at max", MaxBatchSize, MaxBatchSize},
		{"above max", 100, MaxBatchSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{Token: "sc_test", Path: "/tmp", FailOn: "low", Output: "text", BatchSize: tt.input, Server: "http://localhost"}
			if err := c.Validate(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.BatchSize != tt.expected {
				t.Errorf("BatchSize = %d, want %d", c.BatchSize, tt.expected)
			}
		})
	}
}

func TestValidate_FailOnLevels(t *testing.T) {
	valid := []string{"low", "medium", "high", "critical"}
	for _, level := range valid {
		c := Config{Token: "sc_test", Path: "/tmp", FailOn: level, Output: "text", BatchSize: 10, Server: "http://localhost"}
		if err := c.Validate(); err != nil {
			t.Errorf("FailOn=%q should be valid, got error: %v", level, err)
		}
	}

	// Case-insensitive
	c := Config{Token: "sc_test", Path: "/tmp", FailOn: "HIGH", Output: "text", BatchSize: 10, Server: "http://localhost"}
	if err := c.Validate(); err != nil {
		t.Errorf("FailOn=HIGH should be valid (case-insensitive), got error: %v", err)
	}

	// Invalid
	c = Config{Token: "sc_test", Path: "/tmp", FailOn: "extreme", Output: "text", BatchSize: 10, Server: "http://localhost"}
	if err := c.Validate(); err == nil {
		t.Error("FailOn=extreme should be invalid")
	}
}

func TestValidate_OutputFormats(t *testing.T) {
	valid := []string{"text", "json"}
	for _, fmt := range valid {
		c := Config{Token: "sc_test", Path: "/tmp", FailOn: "low", Output: fmt, BatchSize: 10, Server: "http://localhost"}
		if err := c.Validate(); err != nil {
			t.Errorf("Output=%q should be valid, got error: %v", fmt, err)
		}
	}

	c := Config{Token: "sc_test", Path: "/tmp", FailOn: "low", Output: "xml", BatchSize: 10, Server: "http://localhost"}
	if err := c.Validate(); err == nil {
		t.Error("Output=xml should be invalid")
	}
}

func TestValidate_StripTrailingSlash(t *testing.T) {
	c := Config{Token: "sc_test", Path: "/tmp", FailOn: "low", Output: "text", BatchSize: 10, Server: "https://sec-scan.ai/"}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Server != "https://sec-scan.ai" {
		t.Errorf("Server = %q, want trailing slash stripped", c.Server)
	}
}

func TestQuietTruthyValues(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"yes", true},
		{"YES", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("SEC_SCAN_QUIET", tt.env)
			c := &Config{}
			c.ResolveEnv()
			if c.Quiet != tt.want {
				t.Errorf("SEC_SCAN_QUIET=%q: Quiet = %v, want %v", tt.env, c.Quiet, tt.want)
			}
		})
	}
}

func TestResolveEnv_InvalidBatchSize(t *testing.T) {
	clearEnv(t)
	t.Setenv("SEC_SCAN_BATCH_SIZE", "not-a-number")

	c := &Config{}
	c.ResolveEnv()

	if c.BatchSize != DefaultBatchSize {
		t.Errorf("BatchSize = %d, want default %d for invalid env", c.BatchSize, DefaultBatchSize)
	}
}

func clearEnv(t *testing.T) {
	t.Helper()
	envVars := []string{
		"SEC_SCAN_SERVER", "SEC_SCAN_TOKEN", "SEC_SCAN_BATCH_SIZE",
		"SEC_SCAN_FRAMEWORK", "SEC_SCAN_FAIL_ON", "SEC_SCAN_QUIET", "SEC_SCAN_OUTPUT",
	}
	for _, key := range envVars {
		old, existed := os.LookupEnv(key)
		if existed {
			t.Cleanup(func() { os.Setenv(key, old) })
		} else {
			t.Cleanup(func() { os.Unsetenv(key) })
		}
		os.Unsetenv(key)
	}
}
