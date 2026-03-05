package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCache_SetAndGet(t *testing.T) {
	setupTestHome(t)

	excludes := []string{"var/cache", "public/theme"}
	if err := Set("Shopware 6", excludes); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	got := Get("Shopware 6")
	if got == nil {
		t.Fatal("Get() returned nil, want cached excludes")
	}
	if len(got) != 2 || got[0] != "var/cache" || got[1] != "public/theme" {
		t.Errorf("Get() = %v, want %v", got, excludes)
	}
}

func TestCache_MissingSingle(t *testing.T) {
	setupTestHome(t)

	if err := Set("Laravel", []string{"storage/framework/views"}); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	got := Get("Shopware 6")
	if got != nil {
		t.Errorf("Get() = %v, want nil for uncached framework", got)
	}
}

func TestCache_Expired(t *testing.T) {
	setupTestHome(t)

	// Write an expired entry directly
	path := cacheFilePath()
	c := &FrameworkCache{
		Entries: map[string]CacheEntry{
			"Laravel": {
				DefaultExcludes: []string{"storage/framework/views"},
				FetchedAt:       time.Now().Add(-25 * time.Hour),
			},
		},
	}
	data, _ := json.Marshal(c)
	os.WriteFile(path, data, 0o600)

	got := Get("Laravel")
	if got != nil {
		t.Errorf("Get() = %v, want nil for expired entry", got)
	}
}

func TestCache_MissingFile(t *testing.T) {
	setupTestHome(t)

	got := Get("Laravel")
	if got != nil {
		t.Errorf("Get() = %v, want nil when no cache file", got)
	}
}

func TestCache_CorruptFile(t *testing.T) {
	setupTestHome(t)

	path := cacheFilePath()
	os.WriteFile(path, []byte("not json{{{"), 0o600)

	got := Get("Laravel")
	if got != nil {
		t.Errorf("Get() = %v, want nil for corrupt cache", got)
	}
}

func setupTestHome(t *testing.T) {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create the config dir so cache can write
	configDir := filepath.Join(tmpHome, ".sec-scan")
	os.MkdirAll(configDir, 0o700)
}
