package output

import (
	"encoding/json"
	"fmt"
	"os"
)

type jsonOutput struct {
	Summary  jsonSummary      `json:"summary"`
	Files    []jsonFileResult `json:"files"`
	ExitCode int              `json:"exitCode"`
}

type jsonSummary struct {
	TotalFiles  int `json:"totalFiles"`
	UniqueFiles int `json:"uniqueFiles"`
	Secure      int `json:"secure"`
	Insecure    int `json:"insecure"`
	Errors      int `json:"errors"`
	Skipped     int `json:"skipped,omitempty"`
}

type jsonFileResult struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum"`
	Secure   string `json:"secure"`
	Risk     string `json:"risk,omitempty"`
	Details  string `json:"details"`
}

// RenderJSON outputs machine-readable JSON to stdout.
func RenderJSON(summary ScanSummary, exitCode int) {
	out := jsonOutput{
		Summary: jsonSummary{
			TotalFiles:  summary.TotalFiles,
			UniqueFiles: summary.UniqueFiles,
			Secure:      summary.SecureCount,
			Insecure:    summary.InsecureCount,
			Errors:      summary.ErrorCount,
			Skipped:     summary.SkippedCount,
		},
		Files:    make([]jsonFileResult, 0, len(summary.InsecureFiles)+len(summary.ErrorFiles)),
		ExitCode: exitCode,
	}

	for _, f := range summary.InsecureFiles {
		out.Files = append(out.Files, jsonFileResult{
			Path:     f.Path,
			Checksum: f.Checksum,
			Secure:   "no",
			Risk:     f.RiskStr,
			Details:  f.Details,
		})
	}

	for _, f := range summary.ErrorFiles {
		out.Files = append(out.Files, jsonFileResult{
			Path:     f.Path,
			Checksum: f.Checksum,
			Secure:   "error",
			Details:  f.Details,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON output: %v\n", err)
	}
}
