package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
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

func TestRenderText_AllClean(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:  3,
		UniqueFiles: 3,
		SecureCount: 3,
	}

	out := captureStdout(t, func() { RenderText(summary) })

	if !strings.Contains(out, "Total files:    3") {
		t.Errorf("expected total files count, got:\n%s", out)
	}
	if !strings.Contains(out, "All files are clean.") {
		t.Errorf("expected 'All files are clean.' message, got:\n%s", out)
	}
}

func TestRenderText_WithInsecure(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:    2,
		UniqueFiles:   2,
		SecureCount:   1,
		InsecureCount: 1,
		InsecureFiles: []InsecureFile{
			{Path: "evil.php", Checksum: "abc123", Risk: RiskCritical, RiskStr: "critical", Details: "webshell detected"},
		},
	}

	out := captureStdout(t, func() { RenderText(summary) })

	if !strings.Contains(out, "INSECURE:") {
		t.Errorf("expected INSECURE label, got:\n%s", out)
	}
	if !strings.Contains(out, "evil.php") {
		t.Errorf("expected file path, got:\n%s", out)
	}
	if !strings.Contains(out, "webshell detected") {
		t.Errorf("expected details, got:\n%s", out)
	}
}

func TestRenderText_WithErrors(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:  1,
		UniqueFiles: 1,
		ErrorCount:  1,
		ErrorFiles: []ErrorFile{
			{Path: "broken.php", Checksum: "def456", Details: "analysis timeout"},
		},
	}

	out := captureStdout(t, func() { RenderText(summary) })

	if !strings.Contains(out, "Errors:") {
		t.Errorf("expected Errors label, got:\n%s", out)
	}
	if !strings.Contains(out, "broken.php") {
		t.Errorf("expected file path, got:\n%s", out)
	}
}

func TestRenderText_ShowsUniqueWhenDifferent(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:  5,
		UniqueFiles: 3,
		SecureCount: 5,
	}

	out := captureStdout(t, func() { RenderText(summary) })

	if !strings.Contains(out, "Unique files:   3") {
		t.Errorf("expected unique files count when different from total, got:\n%s", out)
	}
}

func TestRenderText_HidesUniqueWhenSame(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:  3,
		UniqueFiles: 3,
		SecureCount: 3,
	}

	out := captureStdout(t, func() { RenderText(summary) })

	if strings.Contains(out, "Unique files:") {
		t.Errorf("should not show unique files when equal to total, got:\n%s", out)
	}
}

func TestRenderText_ShowsSkipped(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:   3,
		UniqueFiles:  3,
		SecureCount:  1,
		SkippedCount: 2,
	}

	out := captureStdout(t, func() { RenderText(summary) })

	if !strings.Contains(out, "Skipped:        2") {
		t.Errorf("expected skipped count, got:\n%s", out)
	}
}

func TestRenderJSON_Structure(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:    3,
		UniqueFiles:   2,
		SecureCount:   1,
		InsecureCount: 1,
		ErrorCount:    1,
		InsecureFiles: []InsecureFile{
			{Path: "vuln.php", Checksum: "aaa", Risk: RiskHigh, RiskStr: "high", Details: "SQLi"},
		},
		ErrorFiles: []ErrorFile{
			{Path: "err.php", Checksum: "bbb", Details: "timeout"},
		},
	}

	out := captureStdout(t, func() { RenderJSON(summary, 1) })

	var result jsonOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, out)
	}

	if result.Summary.TotalFiles != 3 {
		t.Errorf("totalFiles = %d, want 3", result.Summary.TotalFiles)
	}
	if result.Summary.UniqueFiles != 2 {
		t.Errorf("uniqueFiles = %d, want 2", result.Summary.UniqueFiles)
	}
	if result.Summary.Secure != 1 {
		t.Errorf("secure = %d, want 1", result.Summary.Secure)
	}
	if result.Summary.Insecure != 1 {
		t.Errorf("insecure = %d, want 1", result.Summary.Insecure)
	}
	if result.Summary.Errors != 1 {
		t.Errorf("errors = %d, want 1", result.Summary.Errors)
	}
	if result.ExitCode != 1 {
		t.Errorf("exitCode = %d, want 1", result.ExitCode)
	}
	if len(result.Files) != 2 {
		t.Fatalf("files count = %d, want 2", len(result.Files))
	}

	// Insecure file
	if result.Files[0].Path != "vuln.php" {
		t.Errorf("files[0].path = %q, want vuln.php", result.Files[0].Path)
	}
	if result.Files[0].Secure != "no" {
		t.Errorf("files[0].secure = %q, want no", result.Files[0].Secure)
	}
	if result.Files[0].Risk != "high" {
		t.Errorf("files[0].risk = %q, want high", result.Files[0].Risk)
	}

	// Error file
	if result.Files[1].Secure != "error" {
		t.Errorf("files[1].secure = %q, want error", result.Files[1].Secure)
	}
}

func TestRenderJSON_AllClean(t *testing.T) {
	summary := ScanSummary{
		TotalFiles:  2,
		UniqueFiles: 2,
		SecureCount: 2,
	}

	out := captureStdout(t, func() { RenderJSON(summary, 0) })

	var result jsonOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("exitCode = %d, want 0", result.ExitCode)
	}
	if len(result.Files) != 0 {
		t.Errorf("files count = %d, want 0 for all-clean scan", len(result.Files))
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stdout = oldStdout

	return buf.String()
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
