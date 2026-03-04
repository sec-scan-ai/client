package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	colorCritical = color.New(color.FgRed, color.Bold)
	colorHigh     = color.New(color.FgRed)
	colorMedium   = color.New(color.FgYellow)
	colorLow      = color.New(color.FgCyan)
	colorSecure   = color.New(color.FgGreen)
	colorError    = color.New(color.FgMagenta)
	colorBold     = color.New(color.Bold)
)

// Progress prints a progress message to stderr (suppressed in quiet mode).
func Progress(quiet bool, format string, args ...any) {
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// RenderText outputs human-readable colored results to stdout.
func RenderText(summary ScanSummary) {
	w := os.Stdout
	separator := strings.Repeat("=", 60)

	fmt.Fprintln(w)
	fmt.Fprintln(w, separator)
	fmt.Fprintf(w, "%-16s%d\n", "Total files:", summary.TotalFiles)
	if summary.UniqueFiles != summary.TotalFiles {
		fmt.Fprintf(w, "%-16s%d\n", "Unique files:", summary.UniqueFiles)
	}
	colorSecure.Fprintf(w, "%-16s%d\n", "Secure:", summary.SecureCount)
	if summary.InsecureCount > 0 {
		colorCritical.Fprintf(w, "%-16s%d\n", "INSECURE:", summary.InsecureCount)
	} else {
		fmt.Fprintf(w, "%-16s%d\n", "Insecure:", 0)
	}
	if summary.ErrorCount > 0 {
		colorError.Fprintf(w, "%-16s%d\n", "Errors:", summary.ErrorCount)
	}
	if summary.SkippedCount > 0 {
		fmt.Fprintf(w, "%-16s%d\n", "Skipped:", summary.SkippedCount)
	}
	fmt.Fprintln(w, separator)

	for _, f := range summary.InsecureFiles {
		fmt.Fprintln(w)
		printRiskLine(w, f)
		fmt.Fprintf(w, "   Hash:     %s\n", f.Checksum)
		fmt.Fprintf(w, "   Details:  %s\n", f.Details)
	}

	for _, f := range summary.ErrorFiles {
		fmt.Fprintln(w)
		colorError.Fprintf(w, "?? ERROR:    %s\n", f.Path)
		fmt.Fprintf(w, "   Hash:     %s\n", f.Checksum)
		fmt.Fprintf(w, "   Details:  %s\n", f.Details)
	}

	if summary.InsecureCount == 0 && summary.ErrorCount == 0 {
		fmt.Fprintln(w)
		colorSecure.Fprintln(w, "All files are clean.")
	}
	fmt.Fprintln(w)
}

func printRiskLine(w io.Writer, f InsecureFile) {
	label := strings.ToUpper(f.RiskStr)
	switch f.Risk {
	case RiskCritical:
		colorCritical.Fprintf(w, "!! [%s] %s\n", label, f.Path)
	case RiskHigh:
		colorHigh.Fprintf(w, "!! [%s] %s\n", label, f.Path)
	case RiskMedium:
		colorMedium.Fprintf(w, "!! [%s] %s\n", label, f.Path)
	case RiskLow:
		colorLow.Fprintf(w, "!! [%s] %s\n", label, f.Path)
	default:
		fmt.Fprintf(w, "!! [%s] %s\n", label, f.Path)
	}
}
