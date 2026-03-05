package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	apiPkg "github.com/sec-scan-ai/client/internal/api"
	"github.com/sec-scan-ai/client/internal/config"
)

// --- Mock server helpers ---

// mockServer creates a test HTTP server that handles the sec-scan API endpoints.
// lookupHandler receives the decoded LookupRequest and returns a LookupResponse.
// analyzeHandler receives the decoded AnalyzeRequest and returns an AnalyzeResponse.
// Either handler can be nil to return 404.
func mockServer(t *testing.T,
	lookupHandler func(apiPkg.LookupRequest) apiPkg.LookupResponse,
	analyzeHandler func(apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/files/lookup" && r.Method == "POST":
			if lookupHandler == nil {
				w.WriteHeader(404)
				return
			}
			var req apiPkg.LookupRequest
			json.NewDecoder(r.Body).Decode(&req)
			resp := lookupHandler(req)
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/api/files/analyze" && r.Method == "POST":
			if analyzeHandler == nil {
				w.WriteHeader(404)
				return
			}
			var req apiPkg.AnalyzeRequest
			json.NewDecoder(r.Body).Decode(&req)
			resp := analyzeHandler(req)
			json.NewEncoder(w).Encode(resp)

		case strings.HasPrefix(r.URL.Path, "/api/frameworks/") && r.Method == "GET":
			// Always return empty excludes for tests
			json.NewEncoder(w).Encode(apiPkg.FrameworkConfigResponse{})

		default:
			w.WriteHeader(404)
		}
	}))
}

func testConfig(serverURL, dir string) *config.Config {
	return &config.Config{
		Token:             "sc_test",
		Server:            serverURL,
		BatchSize:         10,
		FailOn:            "low",
		Output:            "text",
		Quiet:             true,
		NoDefaultExcludes: true,
		Path:              dir,
	}
}

func writePHP(t *testing.T, dir, name, content string) {
	t.Helper()
	os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

// --- Dry run tests ---

func TestDryRun_ShowsInfoWithoutLookup(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "a.php", "<?php echo 1;")
	writePHP(t, dir, "b.php", "<?php echo 2;")

	stderr := captureStderr(t, func() {
		cfg := testConfig("http://localhost:1", dir)
		cfg.DryRun = true
		cfg.Quiet = false
		exitCode := runScan(cfg)
		if exitCode != 0 {
			t.Errorf("dry-run exit code = %d, want 0", exitCode)
		}
	})

	if !strings.Contains(stderr, "Found 2 PHP file(s)") {
		t.Errorf("expected file count in output, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Unique file(s): 2") {
		t.Errorf("expected unique count in output, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Dry run") {
		t.Errorf("expected dry run message in output, got:\n%s", stderr)
	}
}

func TestDryRun_NeverCallsLookupOrAnalyze(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "test.php", "<?php echo 1;")

	// If dry-run calls lookup or analyze, the server will fail the test
	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			t.Error("dry-run should not call lookup")
			return apiPkg.LookupResponse{}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			t.Error("dry-run should not call analyze")
			return apiPkg.AnalyzeResponse{}
		},
	)
	defer server.Close()

	cfg := testConfig(server.URL, dir)
	cfg.DryRun = true
	exitCode := runScan(cfg)
	if exitCode != 0 {
		t.Fatalf("dry-run exit code = %d, want 0", exitCode)
	}
}

func TestDryRun_ShowsFramework(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "index.php", "<?php echo 1;")
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"require": {"shopware/core": "^6.4"}}`), 0o644)

	stderr := captureStderr(t, func() {
		cfg := testConfig("http://localhost:1", dir)
		cfg.DryRun = true
		cfg.Quiet = false
		runScan(cfg)
	})

	if !strings.Contains(stderr, "Framework: Shopware 6") {
		t.Errorf("expected framework in output, got:\n%s", stderr)
	}
}

// --- Full scan tests ---

func TestScan_FullSuccess(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "clean.php", "<?php echo 'hello';")
	writePHP(t, dir, "vuln.php", "<?php eval($_POST['x']);")

	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			// First checksum is cached, second is unknown
			results := make(map[string]apiPkg.FileResult)
			var unknown []string
			for i, cs := range req.Checksums {
				if i == 0 {
					results[cs] = apiPkg.FileResult{Secure: "yes", Risk: "low", Details: "clean"}
				} else {
					unknown = append(unknown, cs)
				}
			}
			return apiPkg.LookupResponse{Results: results, Unknown: unknown}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			results := make(map[string]apiPkg.FileResult)
			for _, f := range req.Files {
				results[f.Checksum] = apiPkg.FileResult{Secure: "no", Risk: "high", Details: "eval injection"}
			}
			return apiPkg.AnalyzeResponse{Results: results}
		},
	)
	defer server.Close()

	cfg := testConfig(server.URL, dir)
	exitCode := runScan(cfg)

	// Should fail because there's a high-risk finding and fail-on is "low"
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1 (has insecure files)", exitCode)
	}
}

func TestScan_AllCached(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "clean.php", "<?php echo 'cached';")

	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			results := make(map[string]apiPkg.FileResult)
			for _, cs := range req.Checksums {
				results[cs] = apiPkg.FileResult{Secure: "yes", Risk: "low"}
			}
			return apiPkg.LookupResponse{Results: results}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			t.Error("should not call analyze when all files are cached")
			return apiPkg.AnalyzeResponse{}
		},
	)
	defer server.Close()

	cfg := testConfig(server.URL, dir)
	exitCode := runScan(cfg)
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (all cached and clean)", exitCode)
	}
}

func TestScan_ForceMode(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "test.php", "<?php echo 1;")

	var lookupCalled atomic.Bool
	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			lookupCalled.Store(true)
			return apiPkg.LookupResponse{}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			if !req.Force {
				t.Error("force flag not set in analyze request")
			}
			results := make(map[string]apiPkg.FileResult)
			for _, f := range req.Files {
				results[f.Checksum] = apiPkg.FileResult{Secure: "yes"}
			}
			return apiPkg.AnalyzeResponse{Results: results}
		},
	)
	defer server.Close()

	cfg := testConfig(server.URL, dir)
	cfg.Force = true
	exitCode := runScan(cfg)

	if lookupCalled.Load() {
		t.Error("force mode should skip lookup")
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestScan_AuthFailure(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "test.php", "<?php echo 1;")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/frameworks/") {
			json.NewEncoder(w).Encode(apiPkg.FrameworkConfigResponse{})
			return
		}
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(apiPkg.ErrorResponse{StatusCode: 401, Message: "Unauthorized"})
	}))
	defer server.Close()

	cfg := testConfig(server.URL, dir)
	exitCode := runScan(cfg)

	// Lookup fails with 401 - should return error exit code
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1 (auth failure)", exitCode)
	}
}

func TestScan_RateLimit(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "a.php", "<?php echo 1;")
	writePHP(t, dir, "b.php", "<?php echo 2;")

	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			// All files unknown - force analyze
			return apiPkg.LookupResponse{
				Results: make(map[string]apiPkg.FileResult),
				Unknown: req.Checksums,
			}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			// Simulate 429 by panicking - the mock handler won't reach this
			return apiPkg.AnalyzeResponse{}
		},
	)
	defer server.Close()

	// Override the analyze handler to return 429
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/files/lookup":
			var req apiPkg.LookupRequest
			json.NewDecoder(r.Body).Decode(&req)
			resp := apiPkg.LookupResponse{
				Results: make(map[string]apiPkg.FileResult),
				Unknown: req.Checksums,
			}
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/api/files/analyze":
			w.WriteHeader(429)
			json.NewEncoder(w).Encode(apiPkg.ErrorResponse{StatusCode: 429, Message: "Rate limit"})
		case strings.HasPrefix(r.URL.Path, "/api/frameworks/"):
			json.NewEncoder(w).Encode(apiPkg.FrameworkConfigResponse{})
		}
	})

	cfg := testConfig(server.URL, dir)
	// Use text output to avoid stdout capture issues
	stderr := captureStderr(t, func() {
		runScan(cfg)
	})

	if !strings.Contains(stderr, "Rate limit") {
		t.Errorf("expected rate limit error in output, got:\n%s", stderr)
	}
}

func TestScan_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "vuln.php", "<?php eval($_GET['x']);")

	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			return apiPkg.LookupResponse{
				Results: make(map[string]apiPkg.FileResult),
				Unknown: req.Checksums,
			}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			results := make(map[string]apiPkg.FileResult)
			for _, f := range req.Files {
				results[f.Checksum] = apiPkg.FileResult{Secure: "no", Risk: "critical", Details: "eval injection"}
			}
			return apiPkg.AnalyzeResponse{Results: results}
		},
	)
	defer server.Close()

	cfg := testConfig(server.URL, dir)
	cfg.Output = "json"

	stdout := captureStdout(t, func() {
		runScan(cfg)
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, stdout)
	}

	if result["exitCode"].(float64) != 1 {
		t.Errorf("exitCode = %v, want 1", result["exitCode"])
	}

	files := result["files"].([]interface{})
	if len(files) != 1 {
		t.Fatalf("files count = %d, want 1", len(files))
	}

	file := files[0].(map[string]interface{})
	if file["risk"] != "critical" {
		t.Errorf("risk = %v, want critical", file["risk"])
	}
}

func TestScan_FailOnThreshold(t *testing.T) {
	dir := t.TempDir()
	writePHP(t, dir, "vuln.php", "<?php eval($_GET['x']);")

	server := mockServer(t,
		func(req apiPkg.LookupRequest) apiPkg.LookupResponse {
			return apiPkg.LookupResponse{
				Results: make(map[string]apiPkg.FileResult),
				Unknown: req.Checksums,
			}
		},
		func(req apiPkg.AnalyzeRequest) apiPkg.AnalyzeResponse {
			results := make(map[string]apiPkg.FileResult)
			for _, f := range req.Files {
				results[f.Checksum] = apiPkg.FileResult{Secure: "no", Risk: "medium", Details: "issue"}
			}
			return apiPkg.AnalyzeResponse{Results: results}
		},
	)
	defer server.Close()

	// fail-on=high, finding is medium - should pass
	cfg := testConfig(server.URL, dir)
	cfg.FailOn = "high"
	exitCode := runScan(cfg)
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (medium finding below high threshold)", exitCode)
	}

	// fail-on=low, finding is medium - should fail
	cfg2 := testConfig(server.URL, dir)
	cfg2.FailOn = "low"
	exitCode2 := runScan(cfg2)
	if exitCode2 != 1 {
		t.Errorf("exit code = %d, want 1 (medium finding meets low threshold)", exitCode2)
	}
}

func TestScan_NoFiles(t *testing.T) {
	dir := t.TempDir()
	// Empty directory - no PHP files

	cfg := testConfig("http://localhost:1", dir)
	exitCode := runScan(cfg)
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (no files to scan)", exitCode)
	}
}

// --- Helpers ---

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	fn()

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stderr = oldStderr

	return buf.String()
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
