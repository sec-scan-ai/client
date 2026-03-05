package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/sec-scan-ai/client/internal/api"
	"github.com/sec-scan-ai/client/internal/cache"
	"github.com/sec-scan-ai/client/internal/collector"
	"github.com/sec-scan-ai/client/internal/config"
	"github.com/sec-scan-ai/client/internal/framework"
	"github.com/sec-scan-ai/client/internal/output"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func NewRootCmd() *cobra.Command {
	cfg := &config.Config{}

	cmd := &cobra.Command{
		Use:   "sec-scan [flags] <path>",
		Short: "PHP security scanner - scans files for vulnerabilities",
		Long:  "Collects PHP files, computes checksums, and sends them to the sec-scan API for security analysis.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.Help()
				os.Exit(0)
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		Version: fmt.Sprintf("%s (built %s)", Version, BuildTime),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Path = args[0]

			// Handle --force-check alias
			if forceCheck, _ := cmd.Flags().GetBool("force-check"); forceCheck {
				cfg.Force = true
			}

			cfg.ResolveEnv()
			if err := cfg.Validate(); err != nil {
				return err
			}

			exitCode := runScan(cfg)
			os.Exit(exitCode)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&cfg.Server, "server", "s", "", "Server URL (env: SEC_SCAN_SERVER)")
	flags.StringVarP(&cfg.Token, "token", "t", "", "API token (env: SEC_SCAN_TOKEN)")
	flags.IntVarP(&cfg.BatchSize, "batch-size", "b", 0, "Files per analysis batch (env: SEC_SCAN_BATCH_SIZE)")
	flags.StringSliceVarP(&cfg.Excludes, "exclude", "e", nil, "Directories to exclude as relative paths from scan root (repeatable, e.g. vendor, admin/cache)")
	flags.StringVarP(&cfg.Framework, "framework", "f", "", "PHP framework (env: SEC_SCAN_FRAMEWORK, auto-detected if not set)")
	flags.BoolVar(&cfg.Force, "force", false, "Force re-analysis of all files (skip lookup)")
	flags.Bool("force-check", false, "Alias for --force")
	flags.StringVar(&cfg.FailOn, "fail-on", "", "Minimum risk level for exit code 1: low|medium|high|critical (env: SEC_SCAN_FAIL_ON)")
	flags.BoolVarP(&cfg.Quiet, "quiet", "q", false, "Suppress progress output (env: SEC_SCAN_QUIET)")
	flags.StringVarP(&cfg.Output, "output", "o", "", "Output format: text|json (env: SEC_SCAN_OUTPUT)")
	flags.BoolVar(&cfg.NoFollowSymlinks, "no-follow-symlinks", false, "Do not follow symlinks")
	flags.BoolVar(&cfg.NoDefaultExcludes, "no-default-excludes", false, "Skip server-provided default exclude directories")

	// Hide the alias flag from help
	flags.MarkHidden("force-check")

	return cmd
}

func runScan(cfg *config.Config) int {
	followSymlinks := !cfg.NoFollowSymlinks

	// Resolve target path
	target, err := filepath.Abs(cfg.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot resolve path %s: %v\n", cfg.Path, err)
		return 1
	}

	// Detect framework (before file collection so we can fetch default excludes)
	fw := cfg.Framework
	if fw == "" {
		fw = framework.Detect(target)
	}
	output.Progress(cfg.Quiet, "Framework: %s", fw)

	// Fetch default excludes from server and merge with user excludes
	mergedExcludes := cfg.Excludes
	if !cfg.NoDefaultExcludes {
		defaultExcludes := fetchDefaultExcludes(cfg, fw)
		if len(defaultExcludes) > 0 {
			output.Progress(cfg.Quiet, "Default excludes: %s", strings.Join(defaultExcludes, ", "))
			mergedExcludes = mergeExcludes(cfg.Excludes, defaultExcludes)
		}
	}

	// Collect PHP files
	output.Progress(cfg.Quiet, "Scanning %s ...", cfg.Path)
	files, err := collector.CollectPHPFiles(target, mergedExcludes, followSymlinks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if len(files) == 0 {
		output.Progress(cfg.Quiet, "No PHP files found.")
		return 0
	}
	output.Progress(cfg.Quiet, "Found %d PHP file(s)", len(files))

	// Deduplicate by checksum
	type uniqueFile struct {
		file collector.PHPFile
	}
	uniqueMap := make(map[string]uniqueFile)
	for _, f := range files {
		if _, exists := uniqueMap[f.Checksum]; !exists {
			uniqueMap[f.Checksum] = uniqueFile{file: f}
		}
	}

	uniqueChecksums := make([]string, 0, len(uniqueMap))
	for cs := range uniqueMap {
		uniqueChecksums = append(uniqueChecksums, cs)
	}

	client := api.NewClient(cfg.Server, cfg.Token)
	results := make(map[string]api.FileResult)

	var toAnalyze []collector.PHPFile

	if cfg.Force {
		// Force mode: analyze all files
		for _, uf := range uniqueMap {
			toAnalyze = append(toAnalyze, uf.file)
		}
		output.Progress(cfg.Quiet, "Force mode: re-analyzing all %d unique file(s)", len(toAnalyze))
	} else {
		// Lookup phase
		output.Progress(cfg.Quiet, "Looking up %d unique checksum(s) ...", len(uniqueChecksums))
		var spinner *output.Spinner
		if !cfg.Quiet {
			spinner = output.NewSpinner(fmt.Sprintf("Looking up %d checksums", len(uniqueChecksums)))
		}
		lookupResp, err := client.Lookup(uniqueChecksums)
		if spinner != nil {
			spinner.Stop("")
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during lookup: %v\n", err)
			return 1
		}

		for k, v := range lookupResp.Results {
			results[k] = v
		}

		output.Progress(cfg.Quiet, "  %d cached, %d need analysis", len(lookupResp.Results), len(lookupResp.Unknown))

		// Collect unknown files for analysis
		unknownSet := make(map[string]bool)
		for _, cs := range lookupResp.Unknown {
			unknownSet[cs] = true
		}
		for _, uf := range uniqueMap {
			if unknownSet[uf.file.Checksum] {
				toAnalyze = append(toAnalyze, uf.file)
			}
		}
	}

	// Analyze phase - send files concurrently, batch-size controls parallelism
	if len(toAnalyze) > 0 {
		output.Progress(cfg.Quiet, "Analyzing %d file(s) (%d parallel) ...", len(toAnalyze), cfg.BatchSize)

		var progress *output.ProgressSpinner
		if !cfg.Quiet {
			progress = output.NewProgressSpinner(len(toAnalyze))
		}

		// Trap Ctrl+C: stop dispatching new requests, wait for in-flight ones
		var cancelled atomic.Bool
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancelled.Store(true)
			if progress != nil {
				progress.SetCancelled()
			}
			signal.Stop(sigCh)
		}()

		var mu sync.Mutex
		var firstErr error
		sem := make(chan struct{}, cfg.BatchSize)
		var wg sync.WaitGroup

		for _, f := range toAnalyze {
			if cancelled.Load() {
				break
			}

			content, err := collector.ReadContent(f.AbsPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: cannot read %s: %v\n", f.RelPath, err)
				continue
			}

			analyzeFile := api.AnalyzeFile{
				Checksum: f.Checksum,
				Path:     f.RelPath,
				Size:     f.Size,
				Content:  content,
			}

			wg.Add(1)
			if progress != nil {
				progress.AddInflight()
			}
			sem <- struct{}{} // acquire slot
			go func(af api.AnalyzeFile) {
				defer wg.Done()
				defer func() { <-sem }() // release slot

				fileResults, err := client.Analyze([]api.AnalyzeFile{af}, fw, cfg.Force)
				if err != nil {
					if progress != nil {
						progress.IncrementError()
					}
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("%s: %w", af.Path, err)
					}
					mu.Unlock()
					// Stop dispatching on fatal errors (auth, rate limit)
					if apiErr, ok := err.(*api.APIError); ok && (apiErr.StatusCode == 401 || apiErr.StatusCode == 429) {
						cancelled.Store(true)
						if progress != nil {
							progress.SetCancelled()
						}
					}
					return
				}

				mu.Lock()
				for k, v := range fileResults {
					results[k] = v
				}
				mu.Unlock()

				if progress != nil {
					progress.Increment()
				}
			}(analyzeFile)
		}

		wg.Wait()
		signal.Stop(sigCh)
		if progress != nil {
			progress.Stop()
		}

		if firstErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", firstErr)
		}
		if cancelled.Load() {
			fmt.Fprintf(os.Stderr, "Interrupted - showing partial results\n")
		}
	}

	// Build summary and render
	summary := output.BuildSummary(files, results)
	shouldFail := output.ShouldFail(summary, cfg.FailOn)

	exitCode := 0
	if shouldFail {
		exitCode = 1
	}

	if cfg.Output == "json" {
		output.RenderJSON(summary, exitCode)
	} else {
		output.RenderText(summary)
	}

	return exitCode
}

// fetchDefaultExcludes gets default excludes from cache or server.
func fetchDefaultExcludes(cfg *config.Config, fw string) []string {
	// Try cache first
	if cached := cache.Get(fw); cached != nil {
		return cached
	}

	// Fetch from server
	client := api.NewClient(cfg.Server, cfg.Token)
	resp, err := client.FrameworkConfig(fw)
	if err != nil {
		// Non-fatal - continue without defaults
		output.Progress(cfg.Quiet, "Note: no default excludes available for %s", fw)
		return nil
	}

	// Cache the result
	cache.Set(fw, resp.DefaultExcludes)

	return resp.DefaultExcludes
}

// mergeExcludes combines default and user excludes, deduplicating case-insensitively.
func mergeExcludes(userExcludes, defaultExcludes []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, e := range defaultExcludes {
		lower := strings.ToLower(strings.TrimRight(e, "/\\"))
		if !seen[lower] {
			seen[lower] = true
			result = append(result, e)
		}
	}

	for _, e := range userExcludes {
		lower := strings.ToLower(strings.TrimRight(e, "/\\"))
		if !seen[lower] {
			seen[lower] = true
			result = append(result, e)
		}
	}

	return result
}
