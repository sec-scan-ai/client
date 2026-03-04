package framework

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const DefaultFramework = "PHP (unknown framework)"

// Detect walks UP from folder looking for composer.json, then walks DOWN.
// Returns the first framework match, or DefaultFramework if none found.
func Detect(folder string) string {
	absFolder, err := filepath.Abs(folder)
	if err != nil {
		return DefaultFramework
	}

	// Walk up from folder to filesystem root
	current := absFolder
	for {
		composerPath := filepath.Join(current, "composer.json")
		if result := parseFramework(composerPath); result != "" {
			return result
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	// Walk down: find all composer.json files, sorted for deterministic results
	var composerFiles []string
	filepath.WalkDir(absFolder, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && d.Name() == "composer.json" {
			composerFiles = append(composerFiles, path)
		}
		return nil
	})

	sort.Strings(composerFiles)
	for _, path := range composerFiles {
		if result := parseFramework(path); result != "" {
			return result
		}
	}

	return DefaultFramework
}

type composerJSON struct {
	Name       string            `json:"name"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

func parseFramework(composerPath string) string {
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return ""
	}

	var composer composerJSON
	if err := json.Unmarshal(data, &composer); err != nil {
		return ""
	}

	// Merge require + require-dev
	require := make(map[string]string)
	for k, v := range composer.Require {
		require[k] = v
	}
	for k, v := range composer.RequireDev {
		require[k] = v
	}

	// Build lowercase key string for prefix matching
	var keys []string
	for k := range require {
		keys = append(keys, k)
	}
	keysLower := strings.ToLower(strings.Join(keys, " "))

	// OXID eShop
	if strings.Contains(keysLower, "oxid-esales/") {
		ver := require["oxid-esales/oxideshop-ce"]
		if strings.HasPrefix(ver, "v7") || strings.HasPrefix(ver, "7") {
			return "OXID eShop 7.x"
		}
		return "OXID eShop 6.x"
	}

	// Shopware
	if strings.Contains(keysLower, "shopware/") {
		if _, ok := require["shopware/core"]; ok {
			return "Shopware 6"
		}
		if _, ok := require["shopware/platform"]; ok {
			return "Shopware 6"
		}
		return "Shopware 5"
	}

	// Laravel
	if _, ok := require["laravel/framework"]; ok {
		return "Laravel"
	}

	// Symfony
	if _, ok := require["symfony/framework-bundle"]; ok {
		return "Symfony"
	}
	if _, ok := require["symfony/symfony"]; ok {
		return "Symfony"
	}

	// Magento
	if strings.Contains(keysLower, "magento/") {
		return "Magento"
	}

	// WordPress/WooCommerce
	if strings.Contains(keysLower, "woocommerce/") || strings.Contains(keysLower, "wordpress") {
		return "WordPress/WooCommerce"
	}

	// Named project fallback
	if composer.Name != "" {
		return fmt.Sprintf("PHP project (%s)", composer.Name)
	}

	return ""
}
