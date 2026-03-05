package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/sec-scan-ai/client/internal/setup"
)

const (
	cacheFileName = "framework-cache.json"
	cacheTTL      = 24 * time.Hour
)

// FrameworkCache stores cached framework configs with expiry.
type FrameworkCache struct {
	Entries map[string]CacheEntry `json:"entries"`
}

// CacheEntry is a single cached framework config.
type CacheEntry struct {
	DefaultExcludes []string  `json:"default_excludes"`
	FetchedAt       time.Time `json:"fetched_at"`
}

func cacheFilePath() string {
	dir := setup.ConfigDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, cacheFileName)
}

// Get returns cached excludes for a framework, or nil if not cached or expired.
func Get(framework string) []string {
	c := loadCache()
	if c == nil {
		return nil
	}

	entry, ok := c.Entries[framework]
	if !ok {
		return nil
	}

	if time.Since(entry.FetchedAt) > cacheTTL {
		return nil
	}

	return entry.DefaultExcludes
}

// Set stores excludes for a framework in the cache file.
func Set(framework string, excludes []string) error {
	c := loadCache()
	if c == nil {
		c = &FrameworkCache{Entries: make(map[string]CacheEntry)}
	}

	c.Entries[framework] = CacheEntry{
		DefaultExcludes: excludes,
		FetchedAt:       time.Now(),
	}

	return saveCache(c)
}

func loadCache() *FrameworkCache {
	path := cacheFilePath()
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var c FrameworkCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil
	}

	if c.Entries == nil {
		c.Entries = make(map[string]CacheEntry)
	}

	return &c
}

func saveCache(c *FrameworkCache) error {
	path := cacheFilePath()
	if path == "" {
		return nil
	}

	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	// Write to temp file then rename for atomicity
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
