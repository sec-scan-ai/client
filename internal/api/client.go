package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	LookupBatchSize        = 500
	LookupTimeout          = 30 * time.Second
	AnalyzeTimeout         = 300 * time.Second
	FrameworkConfigTimeout = 10 * time.Second
	maxRetries             = 2
)

// Client handles HTTP communication with the sec-scan server.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new API client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL:    baseURL,
		token:      token,
		httpClient: &http.Client{},
	}
}

// Lookup sends checksums to the server and returns cached results + unknowns.
// Automatically batches at LookupBatchSize.
func (c *Client) Lookup(checksums []string) (*LookupResponse, error) {
	merged := &LookupResponse{
		Results: make(map[string]FileResult),
	}

	for i := 0; i < len(checksums); i += LookupBatchSize {
		end := i + LookupBatchSize
		if end > len(checksums) {
			end = len(checksums)
		}
		batch := checksums[i:end]

		resp, err := c.lookupBatch(batch)
		if err != nil {
			return merged, err
		}

		for k, v := range resp.Results {
			merged.Results[k] = v
		}
		merged.Unknown = append(merged.Unknown, resp.Unknown...)
	}

	return merged, nil
}

func (c *Client) lookupBatch(checksums []string) (*LookupResponse, error) {
	body, err := json.Marshal(LookupRequest{Checksums: checksums})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lookup request: %w", err)
	}

	respBody, err := c.doWithRetry("POST", "/api/files/lookup", body, LookupTimeout)
	if err != nil {
		return nil, err
	}

	var result LookupResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse lookup response: %w", err)
	}
	if result.Results == nil {
		result.Results = make(map[string]FileResult)
	}

	return &result, nil
}

// FrameworkConfig fetches default configuration for a framework from the server.
func (c *Client) FrameworkConfig(framework string) (*FrameworkConfigResponse, error) {
	path := "/api/frameworks/" + url.PathEscape(framework)
	respBody, err := c.doWithRetry("GET", path, nil, FrameworkConfigTimeout)
	if err != nil {
		return nil, err
	}

	var result FrameworkConfigResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse framework config response: %w", err)
	}

	return &result, nil
}

// Analyze sends files for analysis.
func (c *Client) Analyze(files []AnalyzeFile, framework string, force bool) (map[string]FileResult, error) {
	body, err := json.Marshal(AnalyzeRequest{
		Files:     files,
		Framework: framework,
		Force:     force,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal analyze request: %w", err)
	}

	respBody, err := c.doWithRetry("POST", "/api/files/analyze", body, AnalyzeTimeout)
	if err != nil {
		return nil, err
	}

	var result AnalyzeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse analyze response: %w", err)
	}
	if result.Results == nil {
		result.Results = make(map[string]FileResult)
	}

	return result.Results, nil
}

func (c *Client) doWithRetry(method, path string, body []byte, timeout time.Duration) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<(attempt-1)) * time.Second // 1s, 2s
			time.Sleep(delay)
		}

		respBody, err := c.doRequest(method, path, body, timeout)
		if err == nil {
			return respBody, nil
		}

		// Don't retry client errors (4xx)
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return nil, err
		}

		lastErr = err
	}

	return nil, lastErr
}

// APIError represents an error response from the server.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case 401:
		return "Authentication failed: invalid or expired API token"
	case 429:
		return fmt.Sprintf("Rate limit exceeded: %s", e.Message)
	default:
		if e.Message != "" {
			return fmt.Sprintf("server error (%d): %s", e.StatusCode, e.Message)
		}
		return fmt.Sprintf("server error (%d)", e.StatusCode)
	}
}

func (c *Client) doRequest(method, path string, body []byte, timeout time.Duration) ([]byte, error) {
	reqURL := c.baseURL + path

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to server at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		msg := string(respBody)
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Message != "" {
			msg = errResp.Message
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	return respBody, nil
}
