package output

import (
	"sort"

	"github.com/sec-scan-ai/client/internal/api"
	"github.com/sec-scan-ai/client/internal/collector"
)

// RiskLevel represents a security risk level with ordering.
type RiskLevel int

const (
	RiskNone     RiskLevel = 0
	RiskLow      RiskLevel = 1
	RiskMedium   RiskLevel = 2
	RiskHigh     RiskLevel = 3
	RiskCritical RiskLevel = 4
)

// ParseRiskLevel converts a string to RiskLevel.
func ParseRiskLevel(s string) RiskLevel {
	switch s {
	case "low":
		return RiskLow
	case "medium":
		return RiskMedium
	case "high":
		return RiskHigh
	case "critical":
		return RiskCritical
	default:
		return RiskNone
	}
}

// RiskString returns the string representation of a RiskLevel.
func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// InsecureFile represents a file that was found to be insecure.
type InsecureFile struct {
	Path     string
	Checksum string
	Risk     RiskLevel
	RiskStr  string
	Details  string
}

// ErrorFile represents a file where analysis failed.
type ErrorFile struct {
	Path     string
	Checksum string
	Details  string
}

// ScanSummary holds aggregated scan statistics.
type ScanSummary struct {
	TotalFiles    int
	UniqueFiles   int
	SecureCount   int
	InsecureCount int
	ErrorCount    int
	SkippedCount  int
	InsecureFiles []InsecureFile
	ErrorFiles    []ErrorFile
}

// BuildSummary creates a ScanSummary from files and results.
// Files may contain duplicates (same checksum). Each file path is reported
// individually, but analysis is deduplicated by checksum.
// Files without a result (e.g. skipped due to interruption) are counted
// separately and not treated as errors.
func BuildSummary(files []collector.PHPFile, results map[string]api.FileResult) ScanSummary {
	summary := ScanSummary{
		TotalFiles: len(files),
	}

	// Count unique checksums
	seen := make(map[string]bool)
	for _, f := range files {
		seen[f.Checksum] = true
	}
	summary.UniqueFiles = len(seen)

	// Map each file to its result
	for _, f := range files {
		result, ok := results[f.Checksum]
		if !ok {
			// No result - file was never sent (e.g. interrupted). Skip silently.
			summary.SkippedCount++
			continue
		}

		if result.Secure == "error" {
			summary.ErrorCount++
			summary.ErrorFiles = append(summary.ErrorFiles, ErrorFile{
				Path:     f.RelPath,
				Checksum: f.Checksum,
				Details:  result.Details,
			})
			continue
		}

		if result.Secure == "yes" {
			summary.SecureCount++
			continue
		}

		// Insecure
		summary.InsecureCount++
		risk := ParseRiskLevel(result.Risk)
		summary.InsecureFiles = append(summary.InsecureFiles, InsecureFile{
			Path:     f.RelPath,
			Checksum: f.Checksum,
			Risk:     risk,
			RiskStr:  result.Risk,
			Details:  result.Details,
		})
	}

	// Sort insecure files by risk (critical first)
	sort.Slice(summary.InsecureFiles, func(i, j int) bool {
		return summary.InsecureFiles[i].Risk > summary.InsecureFiles[j].Risk
	})

	return summary
}

// ShouldFail returns true if any insecure file meets or exceeds the fail-on level.
func ShouldFail(summary ScanSummary, failOn string) bool {
	threshold := ParseRiskLevel(failOn)
	for _, f := range summary.InsecureFiles {
		if f.Risk >= threshold {
			return true
		}
	}
	return false
}
