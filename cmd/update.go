package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const githubRepo = "sec-scan-ai/client"

// githubRelease is a minimal representation of a GitHub release.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func NewUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update sec-scan to the latest version",
		Long:  "Checks GitHub for the latest release, downloads the matching binary, and replaces the current executable.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate()
		},
	}
}

func runUpdate() error {
	currentVersion := strings.TrimPrefix(Version, "v")

	fmt.Fprintf(os.Stderr, "Current version: %s\n", Version)
	fmt.Fprintf(os.Stderr, "Checking for updates...\n")

	// Fetch latest release from GitHub
	release, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	if latestVersion == currentVersion {
		fmt.Fprintf(os.Stderr, "Already up to date (%s)\n", Version)
		return nil
	}

	cmp, err := compareSemver(currentVersion, latestVersion)
	if err == nil && cmp >= 0 {
		fmt.Fprintf(os.Stderr, "Already up to date (%s, latest: %s)\n", Version, release.TagName)
		return nil
	}

	fmt.Fprintf(os.Stderr, "New version available: %s\n", release.TagName)

	// Find the right asset for this OS/arch
	assetName := binaryName()
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no binary found for %s/%s (looked for %s)", runtime.GOOS, runtime.GOARCH, assetName)
	}

	// Get path to current executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	// Resolve symlinks so we replace the actual binary, not the symlink
	execPath, err = resolveExecPath(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Downloading %s...\n", assetName)

	// Download to a temp file next to the current binary
	tmpPath := execPath + ".update"
	if err := downloadFile(downloadURL, tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download failed: %w", err)
	}

	// Make executable
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod failed: %w", err)
	}

	// Replace current binary: rename old to .old, rename new to current, remove old
	oldPath := execPath + ".old"
	os.Remove(oldPath) // clean up any previous .old file

	if err := os.Rename(execPath, oldPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("cannot replace binary (try running with sudo): %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		// Try to restore the old binary
		os.Rename(oldPath, execPath)
		return fmt.Errorf("cannot install new binary: %w", err)
	}

	os.Remove(oldPath)

	fmt.Fprintf(os.Stderr, "Updated to %s\n", release.TagName)
	return nil
}

func fetchLatestRelease() (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &release, nil
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func binaryName() string {
	name := "sec-scan-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// resolveExecPath follows symlinks to find the real binary path.
func resolveExecPath(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return path, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := os.Readlink(path)
		if err != nil {
			return path, err
		}
		return resolved, nil
	}
	return path, nil
}

// compareSemver compares two semver strings (without "v" prefix).
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Pre-release suffixes (e.g. "1.0.0-rc1") are stripped for comparison.
func compareSemver(a, b string) (int, error) {
	partsA, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	partsB, err := parseSemver(b)
	if err != nil {
		return 0, err
	}

	for i := 0; i < 3; i++ {
		if partsA[i] < partsB[i] {
			return -1, nil
		}
		if partsA[i] > partsB[i] {
			return 1, nil
		}
	}
	return 0, nil
}

// parseSemver parses "major.minor.patch" into [3]int.
// Pre-release suffixes after a hyphen are stripped.
func parseSemver(v string) ([3]int, error) {
	// Strip pre-release suffix (e.g. "1.0.0-rc1" -> "1.0.0")
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	var result [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return result, fmt.Errorf("invalid version component %q in %q", parts[i], v)
		}
		result[i] = n
	}
	return result, nil
}
