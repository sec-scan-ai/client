package ignore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validHash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
const validHash2 = "1111111111111111111111111111111111111111111111111111111111111111"

func writeIgnoreFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "ignore")
	os.WriteFile(path, []byte(content), 0o644)
	return path
}

func TestLoad_ValidChecksums(t *testing.T) {
	dir := t.TempDir()
	path := writeIgnoreFile(t, dir, validHash+"\n"+validHash2+"\n")

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d checksums, want 2", len(result))
	}
	if !result[validHash] {
		t.Errorf("missing checksum %s", validHash)
	}
	if !result[validHash2] {
		t.Errorf("missing checksum %s", validHash2)
	}
}

func TestLoad_InlineComments(t *testing.T) {
	dir := t.TempDir()
	content := validHash + "  # admin/xmlrpc.php\n" +
		validHash2 + "\t# lib/legacy.php - false positive\n"
	path := writeIgnoreFile(t, dir, content)

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d checksums, want 2", len(result))
	}
}

func TestLoad_FullLineComments(t *testing.T) {
	dir := t.TempDir()
	content := "# This is a comment\n" +
		"  # Indented comment\n" +
		validHash + "\n"
	path := writeIgnoreFile(t, dir, content)

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d checksums, want 1", len(result))
	}
}

func TestLoad_EmptyLines(t *testing.T) {
	dir := t.TempDir()
	content := "\n\n" + validHash + "\n\n\n"
	path := writeIgnoreFile(t, dir, content)

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d checksums, want 1", len(result))
	}
}

func TestLoad_UppercaseNormalized(t *testing.T) {
	dir := t.TempDir()
	upper := strings.ToUpper(validHash)
	path := writeIgnoreFile(t, dir, upper+"\n")

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result[validHash] {
		t.Errorf("uppercase hash should be normalized to lowercase")
	}
}

func TestLoad_InvalidLineWrongLength(t *testing.T) {
	dir := t.TempDir()
	content := "tooshort\n" + validHash + "\n"
	path := writeIgnoreFile(t, dir, content)

	stderr := captureStderr(t, func() {
		result, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("got %d checksums, want 1 (valid only)", len(result))
		}
	})

	if !strings.Contains(stderr, "line 1") {
		t.Errorf("expected warning with line number, got: %s", stderr)
	}
}

func TestLoad_InvalidLineNonHex(t *testing.T) {
	dir := t.TempDir()
	nonHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	content := nonHex + "\n" + validHash + "\n"
	path := writeIgnoreFile(t, dir, content)

	stderr := captureStderr(t, func() {
		result, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("got %d checksums, want 1 (valid only)", len(result))
		}
	})

	if !strings.Contains(stderr, "invalid hex") {
		t.Errorf("expected hex warning, got: %s", stderr)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	result, err := Load("/nonexistent/path/ignore")
	if err != nil {
		t.Fatalf("missing file should not be an error, got: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("got %d checksums, want 0", len(result))
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeIgnoreFile(t, dir, "")

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("got %d checksums, want 0", len(result))
	}
}

func TestLoad_DuplicateChecksums(t *testing.T) {
	dir := t.TempDir()
	content := validHash + "\n" + validHash + "\n"
	path := writeIgnoreFile(t, dir, content)

	result, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d checksums, want 1 (deduplicated)", len(result))
	}
}

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
