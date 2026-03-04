package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLookup_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/files/lookup" {
			t.Errorf("path = %s, want /api/files/lookup", r.URL.Path)
		}

		var req LookupRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := LookupResponse{
			Results: map[string]FileResult{
				"abc123": {Secure: "yes", Risk: "low", Details: "clean file"},
			},
			Unknown: []string{"def456"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_testtoken")
	resp, err := client.Lookup([]string{"abc123", "def456"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Results) != 1 {
		t.Errorf("results count = %d, want 1", len(resp.Results))
	}
	if resp.Results["abc123"].Secure != "yes" {
		t.Errorf("abc123 secure = %q, want yes", resp.Results["abc123"].Secure)
	}
	if len(resp.Unknown) != 1 || resp.Unknown[0] != "def456" {
		t.Errorf("unknown = %v, want [def456]", resp.Unknown)
	}
}

func TestLookup_Batching(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		var req LookupRequest
		json.NewDecoder(r.Body).Decode(&req)

		if len(req.Checksums) > LookupBatchSize {
			t.Errorf("batch size = %d, exceeds limit %d", len(req.Checksums), LookupBatchSize)
		}

		resp := LookupResponse{
			Results: make(map[string]FileResult),
		}
		for _, cs := range req.Checksums {
			resp.Results[cs] = FileResult{Secure: "yes", Risk: "low"}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create more checksums than one batch (unique values)
	checksums := make([]string, LookupBatchSize+50)
	for i := range checksums {
		checksums[i] = fmt.Sprintf("%064d", i)
	}

	client := NewClient(server.URL, "sc_test")
	resp, err := client.Lookup(checksums)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if requestCount.Load() != 2 {
		t.Errorf("request count = %d, want 2 (batched)", requestCount.Load())
	}
	if len(resp.Results) != len(checksums) {
		t.Errorf("results count = %d, want %d", len(resp.Results), len(checksums))
	}
}

func TestAnalyze_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/files/analyze" {
			t.Errorf("path = %s, want /api/files/analyze", r.URL.Path)
		}

		var req AnalyzeRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Framework != "Shopware 6" {
			t.Errorf("framework = %q, want %q", req.Framework, "Shopware 6")
		}
		if !req.Force {
			t.Error("force should be true")
		}

		resp := AnalyzeResponse{
			Results: map[string]FileResult{
				"hash1": {Secure: "no", Risk: "critical", Details: "webshell detected"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_test")
	files := []AnalyzeFile{
		{Checksum: "hash1", Path: "test.php", Size: 100, Content: "<?php eval($_POST['e']);"},
	}
	results, err := client.Analyze(files, "Shopware 6", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if results["hash1"].Risk != "critical" {
		t.Errorf("risk = %q, want critical", results["hash1"].Risk)
	}
}

func TestAuthHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sc_mytoken" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer sc_mytoken")
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		json.NewEncoder(w).Encode(LookupResponse{Results: map[string]FileResult{}})
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_mytoken")
	client.Lookup([]string{"test"})
}

func TestError_401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(ErrorResponse{StatusCode: 401, Message: "Unauthorized"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_bad")
	_, err := client.Lookup([]string{"test"})
	if err == nil {
		t.Fatal("expected error for 401")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("status = %d, want 401", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "Authentication failed") {
		t.Errorf("error message = %q, want to contain 'Authentication failed'", apiErr.Error())
	}
}

func TestError_429(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(ErrorResponse{
			StatusCode: 429,
			Message:    "Daily analyze limit exceeded (100/100)",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_test")
	_, err := client.Analyze([]AnalyzeFile{{Checksum: "x"}}, "PHP", false)
	if err == nil {
		t.Fatal("expected error for 429")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 429 {
		t.Errorf("status = %d, want 429", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "Rate limit exceeded") {
		t.Errorf("error message = %q, want to contain 'Rate limit exceeded'", apiErr.Error())
	}
}

func TestError_500_Retry(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count <= 2 {
			w.WriteHeader(500)
			io.WriteString(w, `{"message": "internal error"}`)
			return
		}
		// Third attempt succeeds
		json.NewEncoder(w).Encode(LookupResponse{
			Results: map[string]FileResult{"ok": {Secure: "yes"}},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_test")
	resp, err := client.Lookup([]string{"ok"})
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if resp.Results["ok"].Secure != "yes" {
		t.Errorf("expected successful result after retry")
	}
	if attempts.Load() != 3 {
		t.Errorf("attempts = %d, want 3 (initial + 2 retries)", attempts.Load())
	}
}

func TestError_500_AllRetriesFail(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(500)
		io.WriteString(w, `{"message": "persistent error"}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_test")
	_, err := client.Lookup([]string{"test"})
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
	if attempts.Load() != 3 {
		t.Errorf("attempts = %d, want 3", attempts.Load())
	}
}

func TestError_400_NoRetry(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Checksum mismatch for test.php"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "sc_test")
	_, err := client.Analyze([]AnalyzeFile{{Checksum: "x"}}, "PHP", false)
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want 1 (no retry for 4xx)", attempts.Load())
	}
}
