package api

// LookupRequest is sent to POST /api/files/lookup.
type LookupRequest struct {
	Checksums []string `json:"checksums"`
}

// LookupResponse is the server response from /api/files/lookup.
type LookupResponse struct {
	Results map[string]FileResult `json:"results"`
	Unknown []string              `json:"unknown"`
}

// FileResult represents the analysis result for a single file.
type FileResult struct {
	Secure  string `json:"secure"`
	Risk    string `json:"risk"`
	Details string `json:"details"`
}

// AnalyzeRequest is sent to POST /api/files/analyze.
type AnalyzeRequest struct {
	Files     []AnalyzeFile `json:"files"`
	Framework string        `json:"framework"`
	Force     bool          `json:"force,omitempty"`
}

// AnalyzeFile is a single file in an analyze request.
type AnalyzeFile struct {
	Checksum string `json:"checksum"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
}

// AnalyzeResponse is the server response from /api/files/analyze.
type AnalyzeResponse struct {
	Results map[string]FileResult `json:"results"`
}

// ErrorResponse represents an error response from the server.
type ErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

// FrameworkConfigResponse is the server response from GET /api/frameworks/{name}.
type FrameworkConfigResponse struct {
	DefaultExcludes []string `json:"default_excludes"`
}
