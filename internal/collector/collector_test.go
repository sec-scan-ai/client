package collector

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectPHPFiles_BasicCollection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.php", "<?php echo 1;")
	writeFile(t, dir, "b.php", "<?php echo 2;")
	writeFile(t, dir, "c.txt", "not php")

	files, err := CollectPHPFiles(dir, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}

	names := make(map[string]bool)
	for _, f := range files {
		names[f.RelPath] = true
	}
	if !names["a.php"] || !names["b.php"] {
		t.Errorf("expected a.php and b.php, got %v", names)
	}
}

func TestCollectPHPFiles_Nested(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "root.php", "<?php")
	os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755)
	writeFile(t, filepath.Join(dir, "sub"), "sub.php", "<?php")
	writeFile(t, filepath.Join(dir, "sub", "deep"), "deep.php", "<?php")

	files, err := CollectPHPFiles(dir, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
}

func TestCollectPHPFiles_ExcludeDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.php", "<?php")
	os.MkdirAll(filepath.Join(dir, "vendor"), 0o755)
	writeFile(t, filepath.Join(dir, "vendor"), "skip.php", "<?php")
	os.MkdirAll(filepath.Join(dir, "src"), 0o755)
	writeFile(t, filepath.Join(dir, "src"), "keep2.php", "<?php")

	files, err := CollectPHPFiles(dir, []string{"vendor"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	for _, f := range files {
		if strings.Contains(f.RelPath, "vendor") {
			t.Errorf("vendor file should be excluded: %s", f.RelPath)
		}
	}
}

func TestCollectPHPFiles_ExcludeCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.php", "<?php")
	os.MkdirAll(filepath.Join(dir, "Vendor"), 0o755)
	writeFile(t, filepath.Join(dir, "Vendor"), "skip.php", "<?php")

	files, err := CollectPHPFiles(dir, []string{"vendor"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1 (Vendor dir should be excluded)", len(files))
	}
}

func TestCollectPHPFiles_NestedExclude(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a", "vendor", "b"), 0o755)
	writeFile(t, filepath.Join(dir, "a", "vendor", "b"), "skip.php", "<?php")
	writeFile(t, dir, "keep.php", "<?php")

	// "vendor" only excludes <root>/vendor, not <root>/a/vendor
	files, err := CollectPHPFiles(dir, []string{"vendor"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2 (vendor only excludes root-level)", len(files))
	}

	// Use path to exclude the nested one
	files, err = CollectPHPFiles(dir, []string{"a/vendor"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
}

func TestCollectPHPFiles_SingleFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "test.php", "<?php echo 1;")

	files, err := CollectPHPFiles(filepath.Join(dir, "test.php"), nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
}

func TestCollectPHPFiles_SingleFileNonPHP(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "test.txt", "not php")

	_, err := CollectPHPFiles(filepath.Join(dir, "test.txt"), nil, false)
	if err == nil {
		t.Fatal("expected error for non-.php file")
	}
}

func TestCollectPHPFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	files, err := CollectPHPFiles(dir, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("got %d files, want 0", len(files))
	}
}

func TestCollectPHPFiles_NonExistent(t *testing.T) {
	_, err := CollectPHPFiles("/nonexistent/path", nil, false)
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestFileChecksum(t *testing.T) {
	dir := t.TempDir()
	content := "<?php echo 'hello';"
	writeFile(t, dir, "test.php", content)

	got, err := FileChecksum(filepath.Join(dir, "test.php"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if got != expected {
		t.Errorf("checksum = %q, want %q", got, expected)
	}
}

func TestReadContent_Normal(t *testing.T) {
	dir := t.TempDir()
	content := "<?php echo 'test';"
	writeFile(t, dir, "test.php", content)

	got, err := ReadContent(filepath.Join(dir, "test.php"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != content {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestReadContent_Truncation(t *testing.T) {
	dir := t.TempDir()
	// Create a file larger than MaxFileSize
	content := strings.Repeat("x", MaxFileSize+100)
	writeFile(t, dir, "big.php", content)

	got, err := ReadContent(filepath.Join(dir, "big.php"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(got, "\n... [truncated]") {
		t.Error("truncated file should end with truncation marker")
	}
	// Content before marker should be exactly MaxFileSize bytes
	parts := strings.SplitN(got, "\n... [truncated]", 2)
	if len(parts[0]) != MaxFileSize {
		t.Errorf("truncated content length = %d, want %d", len(parts[0]), MaxFileSize)
	}
}

func TestReadContent_ExactlyMaxSize(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("x", MaxFileSize)
	writeFile(t, dir, "exact.php", content)

	got, err := ReadContent(filepath.Join(dir, "exact.php"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "[truncated]") {
		t.Error("file exactly at max size should NOT be truncated")
	}
}

func TestCollectPHPFiles_RelPathSlashes(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	writeFile(t, filepath.Join(dir, "sub"), "test.php", "<?php")

	files, err := CollectPHPFiles(dir, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	// RelPath should use forward slashes (for server compatibility)
	if files[0].RelPath != "sub/test.php" {
		t.Errorf("RelPath = %q, want %q", files[0].RelPath, "sub/test.php")
	}
}

func TestCollectPHPFiles_FollowSymlinks(t *testing.T) {
	// Create a directory OUTSIDE the scan root with a PHP file
	externalDir := t.TempDir()
	writeFile(t, externalDir, "external.php", "<?php")

	// Create the scan root with a symlink pointing outside
	scanDir := t.TempDir()
	writeFile(t, scanDir, "local.php", "<?php")
	linkDir := filepath.Join(scanDir, "linked")
	if err := os.Symlink(externalDir, linkDir); err != nil {
		t.Skip("cannot create symlinks on this system")
	}

	// With symlinks followed, should find both local and external file
	files, err := CollectPHPFiles(scanDir, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2 (local + linked external)", len(files))
	}

	// Without following symlinks, only the local file
	files, err = CollectPHPFiles(scanDir, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1 (only local)", len(files))
	}
}

func TestCollectPHPFiles_SymlinkLoop(t *testing.T) {
	dir := t.TempDir()

	// Create a directory with a PHP file
	subDir := filepath.Join(dir, "sub")
	os.MkdirAll(subDir, 0o755)
	writeFile(t, subDir, "test.php", "<?php")

	// Create circular symlink: sub/loop -> dir (parent)
	if err := os.Symlink(dir, filepath.Join(subDir, "loop")); err != nil {
		t.Skip("cannot create symlinks on this system")
	}

	// Should not infinite loop
	files, err := CollectPHPFiles(dir, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find the file but not loop forever
	if len(files) < 1 {
		t.Fatal("should find at least 1 file")
	}
}

func TestCollectPHPFiles_PathBasedExclude(t *testing.T) {
	dir := t.TempDir()

	// Create admin/templates_c/shell.php (should be excluded)
	os.MkdirAll(filepath.Join(dir, "admin", "templates_c"), 0o755)
	writeFile(t, filepath.Join(dir, "admin", "templates_c"), "shell.php", "<?php")

	// Create shop/templates_c/legit.php (should NOT be excluded)
	os.MkdirAll(filepath.Join(dir, "shop", "templates_c"), 0o755)
	writeFile(t, filepath.Join(dir, "shop", "templates_c"), "legit.php", "<?php")

	writeFile(t, dir, "root.php", "<?php")

	files, err := CollectPHPFiles(dir, []string{"admin/templates_c"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2 (root.php + shop/templates_c/legit.php)", len(files))
	}
	for _, f := range files {
		if strings.Contains(f.RelPath, "admin/templates_c") {
			t.Errorf("admin/templates_c should be excluded: %s", f.RelPath)
		}
	}
}

func TestCollectPHPFiles_PathBasedExcludeWithSymlinks(t *testing.T) {
	dir := t.TempDir()

	// Create admin/templates_c/shell.php (should be excluded)
	os.MkdirAll(filepath.Join(dir, "admin", "templates_c"), 0o755)
	writeFile(t, filepath.Join(dir, "admin", "templates_c"), "shell.php", "<?php")

	// Create shop/templates_c/legit.php (should NOT be excluded)
	os.MkdirAll(filepath.Join(dir, "shop", "templates_c"), 0o755)
	writeFile(t, filepath.Join(dir, "shop", "templates_c"), "legit.php", "<?php")

	writeFile(t, dir, "root.php", "<?php")

	files, err := CollectPHPFiles(dir, []string{"admin/templates_c"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2 (root.php + shop/templates_c/legit.php)", len(files))
	}
	for _, f := range files {
		if strings.Contains(f.RelPath, "admin/templates_c") {
			t.Errorf("admin/templates_c should be excluded: %s", f.RelPath)
		}
	}
}

func TestCollectPHPFiles_MultipleExcludes(t *testing.T) {
	dir := t.TempDir()

	// vendor at root - excluded by "vendor"
	os.MkdirAll(filepath.Join(dir, "vendor"), 0o755)
	writeFile(t, filepath.Join(dir, "vendor"), "v.php", "<?php")

	// vendor nested - NOT excluded by "vendor" (only matches root-level)
	os.MkdirAll(filepath.Join(dir, "src", "vendor"), 0o755)
	writeFile(t, filepath.Join(dir, "src", "vendor"), "v2.php", "<?php")

	// admin/cache excluded by path
	os.MkdirAll(filepath.Join(dir, "admin", "cache"), 0o755)
	writeFile(t, filepath.Join(dir, "admin", "cache"), "c.php", "<?php")

	// shop/cache NOT excluded
	os.MkdirAll(filepath.Join(dir, "shop", "cache"), 0o755)
	writeFile(t, filepath.Join(dir, "shop", "cache"), "c2.php", "<?php")

	writeFile(t, dir, "root.php", "<?php")

	files, err := CollectPHPFiles(dir, []string{"vendor", "admin/cache"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have: root.php + src/vendor/v2.php + shop/cache/c2.php = 3
	if len(files) != 3 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = f.RelPath
		}
		t.Fatalf("got %d files %v, want 3 (root.php + src/vendor/v2.php + shop/cache/c2.php)", len(files), names)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
}
