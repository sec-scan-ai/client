package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultServer    = "http://localhost:3000"
	DefaultBatchSize = 10
	MinBatchSize     = 1
	MaxBatchSize     = 50
	DefaultFailOn    = "low"
	DefaultOutput    = "text"
)

// Config holds all resolved configuration for a scan run.
type Config struct {
	Server           string
	Token            string
	BatchSize        int
	Excludes         []string
	Framework        string
	Force            bool
	FailOn           string
	Quiet            bool
	Output           string
	NoFollowSymlinks  bool
	NoDefaultExcludes bool
	Path              string
}

// ValidFailOnLevels are the accepted values for --fail-on.
var ValidFailOnLevels = []string{"low", "medium", "high", "critical"}

// ValidOutputFormats are the accepted values for --output.
var ValidOutputFormats = []string{"text", "json"}

// ResolveEnv fills in any zero-value fields from environment variables.
// Flag values (non-zero) always take precedence.
func (c *Config) ResolveEnv() {
	if c.Server == "" {
		if v := os.Getenv("SEC_SCAN_SERVER"); v != "" {
			c.Server = v
		} else {
			c.Server = DefaultServer
		}
	}
	if c.Token == "" {
		c.Token = os.Getenv("SEC_SCAN_TOKEN")
	}
	if c.BatchSize == 0 {
		if v := os.Getenv("SEC_SCAN_BATCH_SIZE"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				c.BatchSize = n
			}
		}
		if c.BatchSize == 0 {
			c.BatchSize = DefaultBatchSize
		}
	}
	if c.Framework == "" {
		c.Framework = os.Getenv("SEC_SCAN_FRAMEWORK")
	}
	if c.FailOn == "" {
		if v := os.Getenv("SEC_SCAN_FAIL_ON"); v != "" {
			c.FailOn = v
		} else {
			c.FailOn = DefaultFailOn
		}
	}
	if !c.Quiet {
		c.Quiet = isTruthy(os.Getenv("SEC_SCAN_QUIET"))
	}
	if c.Output == "" {
		if v := os.Getenv("SEC_SCAN_OUTPUT"); v != "" {
			c.Output = v
		} else {
			c.Output = DefaultOutput
		}
	}
}

// Validate checks that all required fields are set and values are within allowed ranges.
func (c *Config) Validate() error {
	if c.Token == "" {
		return fmt.Errorf("API token is required (use --token or SEC_SCAN_TOKEN)")
	}
	if c.Path == "" {
		return fmt.Errorf("scan path is required")
	}

	// Clamp batch size
	if c.BatchSize < MinBatchSize {
		c.BatchSize = MinBatchSize
	}
	if c.BatchSize > MaxBatchSize {
		c.BatchSize = MaxBatchSize
	}

	// Validate fail-on level
	c.FailOn = strings.ToLower(c.FailOn)
	if !contains(ValidFailOnLevels, c.FailOn) {
		return fmt.Errorf("invalid --fail-on level %q (must be one of: %s)", c.FailOn, strings.Join(ValidFailOnLevels, ", "))
	}

	// Validate output format
	c.Output = strings.ToLower(c.Output)
	if !contains(ValidOutputFormats, c.Output) {
		return fmt.Errorf("invalid --output format %q (must be one of: %s)", c.Output, strings.Join(ValidOutputFormats, ", "))
	}

	// Strip trailing slash from server URL
	c.Server = strings.TrimRight(c.Server, "/")

	return nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func isTruthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes"
}
