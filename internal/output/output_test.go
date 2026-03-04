package output

import (
	"testing"

	"github.com/sec-scan-ai/client/internal/api"
	"github.com/sec-scan-ai/client/internal/collector"
)

func TestParseRiskLevel(t *testing.T) {
	tests := []struct {
		input string
		want  RiskLevel
	}{
		{"low", RiskLow},
		{"medium", RiskMedium},
		{"high", RiskHigh},
		{"critical", RiskCritical},
		{"unknown", RiskNone},
		{"", RiskNone},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseRiskLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseRiskLevel(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildSummary_Counts(t *testing.T) {
	files := []collector.PHPFile{
		{RelPath: "clean.php", Checksum: "aaa"},
		{RelPath: "vuln.php", Checksum: "bbb"},
		{RelPath: "error.php", Checksum: "ccc"},
		{RelPath: "missing.php", Checksum: "ddd"},
	}
	results := map[string]api.FileResult{
		"aaa": {Secure: "yes", Risk: "low"},
		"bbb": {Secure: "no", Risk: "high", Details: "SQLi"},
		"ccc": {Secure: "error", Details: "analysis timeout"},
		// "ddd" intentionally missing
	}

	summary := BuildSummary(files, results)

	if summary.TotalFiles != 4 {
		t.Errorf("TotalFiles = %d, want 4", summary.TotalFiles)
	}
	if summary.SecureCount != 1 {
		t.Errorf("SecureCount = %d, want 1", summary.SecureCount)
	}
	if summary.InsecureCount != 1 {
		t.Errorf("InsecureCount = %d, want 1", summary.InsecureCount)
	}
	if summary.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1 (server error only)", summary.ErrorCount)
	}
	if summary.SkippedCount != 1 {
		t.Errorf("SkippedCount = %d, want 1 (missing result)", summary.SkippedCount)
	}
}

func TestBuildSummary_UniqueFiles(t *testing.T) {
	// Two files with same checksum
	files := []collector.PHPFile{
		{RelPath: "a.php", Checksum: "same"},
		{RelPath: "b.php", Checksum: "same"},
		{RelPath: "c.php", Checksum: "diff"},
	}
	results := map[string]api.FileResult{
		"same": {Secure: "yes"},
		"diff": {Secure: "yes"},
	}

	summary := BuildSummary(files, results)

	if summary.TotalFiles != 3 {
		t.Errorf("TotalFiles = %d, want 3", summary.TotalFiles)
	}
	if summary.UniqueFiles != 2 {
		t.Errorf("UniqueFiles = %d, want 2", summary.UniqueFiles)
	}
}

func TestBuildSummary_RiskSorting(t *testing.T) {
	files := []collector.PHPFile{
		{RelPath: "low.php", Checksum: "a"},
		{RelPath: "critical.php", Checksum: "b"},
		{RelPath: "medium.php", Checksum: "c"},
		{RelPath: "high.php", Checksum: "d"},
	}
	results := map[string]api.FileResult{
		"a": {Secure: "no", Risk: "low", Details: "minor"},
		"b": {Secure: "no", Risk: "critical", Details: "webshell"},
		"c": {Secure: "no", Risk: "medium", Details: "partial"},
		"d": {Secure: "no", Risk: "high", Details: "sqli"},
	}

	summary := BuildSummary(files, results)

	if len(summary.InsecureFiles) != 4 {
		t.Fatalf("InsecureFiles count = %d, want 4", len(summary.InsecureFiles))
	}

	expectedOrder := []string{"critical", "high", "medium", "low"}
	for i, expected := range expectedOrder {
		if summary.InsecureFiles[i].RiskStr != expected {
			t.Errorf("InsecureFiles[%d].RiskStr = %q, want %q", i, summary.InsecureFiles[i].RiskStr, expected)
		}
	}
}

func TestShouldFail(t *testing.T) {
	tests := []struct {
		name   string
		risks  []string
		failOn string
		want   bool
	}{
		{"no files", nil, "low", false},
		{"low meets low", []string{"low"}, "low", true},
		{"low below medium", []string{"low"}, "medium", false},
		{"medium meets medium", []string{"medium"}, "medium", true},
		{"medium below high", []string{"medium"}, "high", false},
		{"high meets high", []string{"high"}, "high", true},
		{"high below critical", []string{"high"}, "critical", false},
		{"critical meets critical", []string{"critical"}, "critical", true},
		{"mixed - one meets threshold", []string{"low", "high"}, "high", true},
		{"mixed - none meets threshold", []string{"low", "medium"}, "high", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := ScanSummary{}
			for _, r := range tt.risks {
				summary.InsecureFiles = append(summary.InsecureFiles, InsecureFile{
					Risk:    ParseRiskLevel(r),
					RiskStr: r,
				})
			}

			got := ShouldFail(summary, tt.failOn)
			if got != tt.want {
				t.Errorf("ShouldFail(risks=%v, failOn=%q) = %v, want %v", tt.risks, tt.failOn, got, tt.want)
			}
		})
	}
}
