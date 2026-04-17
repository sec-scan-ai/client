package framework

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const DefaultFramework = "PHP (unknown framework)"

// Detect tries composer.lock then composer.json in the scan directory,
// then walks UP toward the user's home directory. Returns DefaultFramework
// if none found.
//
// The walk stops at $HOME (or at the filesystem root if the scan path is
// outside $HOME) to prevent an attacker-controlled composer.json in a
// parent directory (e.g. /tmp/composer.json, $HOME/composer.json) from
// influencing the framework hint sent to the server.
func Detect(folder string) string {
	absFolder, err := filepath.Abs(folder)
	if err != nil {
		return DefaultFramework
	}

	stopAt := detectBoundary(absFolder)

	current := absFolder
	for {
		// Try composer.lock first (has exact installed versions)
		lockPath := filepath.Join(current, "composer.lock")
		if result := parseLockFramework(lockPath); result != "" {
			return result
		}

		// Fall back to composer.json
		composerPath := filepath.Join(current, "composer.json")
		if result := parseComposerFramework(composerPath); result != "" {
			return result
		}

		if current == stopAt {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return DefaultFramework
}

// detectBoundary returns the directory where the walk-up should stop.
// Prefers $HOME when the scan path is inside the user's home directory.
// Otherwise stops at the filesystem root (by returning "/" or the
// equivalent, which filepath.Dir(current) == current will reach naturally).
func detectBoundary(absFolder string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		return ""
	}
	sep := string(filepath.Separator)
	if absFolder == absHome || strings.HasPrefix(absFolder, absHome+sep) {
		return absHome
	}
	return ""
}

// matchFramework takes a map of package names to versions and returns the detected framework.
// projectName is used for the named-project fallback (from composer.json name field).
func matchFramework(packages map[string]string, projectName string) string {
	// Build lowercase key string for prefix matching
	var keys []string
	for k := range packages {
		keys = append(keys, k)
	}
	keysLower := strings.ToLower(strings.Join(keys, " "))

	// OXID eShop
	if strings.Contains(keysLower, "oxid-esales/") {
		ver := packages["oxid-esales/oxideshop-ce"]
		if strings.HasPrefix(ver, "v7") || strings.HasPrefix(ver, "7") {
			return "OXID eShop 7.x"
		}
		return "OXID eShop 6.x"
	}

	// Shopware
	if strings.Contains(keysLower, "shopware/") || projectName == "shopware/platform" || projectName == "shopware/core" {
		if _, ok := packages["shopware/core"]; ok {
			return "Shopware 6"
		}
		if _, ok := packages["shopware/platform"]; ok {
			return "Shopware 6"
		}
		if projectName == "shopware/platform" || projectName == "shopware/core" {
			return "Shopware 6"
		}
		return "Shopware 5"
	}

	// Laravel
	if _, ok := packages["laravel/framework"]; ok {
		return "Laravel"
	}

	// Sylius (checked before Symfony - Sylius depends on symfony/framework-bundle)
	if ver, ok := packages["sylius/sylius"]; ok {
		v := strings.TrimLeft(ver, "^~>=< v")
		if strings.HasPrefix(v, "2") {
			return "Sylius 2.x"
		}
		if strings.HasPrefix(v, "1") {
			return "Sylius 1.x"
		}
		return "Sylius"
	}
	if projectName == "sylius/sylius" {
		return "Sylius"
	}

	// Symfony
	if _, ok := packages["symfony/framework-bundle"]; ok {
		return "Symfony"
	}
	if _, ok := packages["symfony/symfony"]; ok {
		return "Symfony"
	}

	// Magento
	if strings.Contains(keysLower, "magento/") {
		if _, ok := packages["magento/framework"]; ok {
			return "Magento 2"
		}
		if _, ok := packages["magento/product-community-edition"]; ok {
			return "Magento 2"
		}
		if _, ok := packages["magento/product-enterprise-edition"]; ok {
			return "Magento 2"
		}
		return "Magento 1"
	}

	// WordPress/WooCommerce
	if strings.Contains(keysLower, "woocommerce/") || strings.Contains(keysLower, "wordpress") {
		return "WordPress/WooCommerce"
	}

	// JTL-Shop
	if strings.Contains(keysLower, "jtl-shop/") || strings.Contains(keysLower, "jtl/") {
		return "JTL-Shop 5"
	}

	// PrestaShop
	if _, ok := packages["prestashop/prestashop"]; ok {
		return "PrestaShop"
	}

	// Named project fallback (only from composer.json, not lock files)
	if projectName != "" {
		return fmt.Sprintf("PHP project (%s)", projectName)
	}

	return ""
}

// composer.json types

type composerJSON struct {
	Name       string            `json:"name"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

func parseComposerFramework(composerPath string) string {
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return ""
	}

	var composer composerJSON
	if err := json.Unmarshal(data, &composer); err != nil {
		return ""
	}

	packages := make(map[string]string)
	for k, v := range composer.Require {
		packages[k] = v
	}
	for k, v := range composer.RequireDev {
		packages[k] = v
	}

	return matchFramework(packages, composer.Name)
}

// composer.lock types

type composerLock struct {
	Packages    []lockPackage `json:"packages"`
	PackagesDev []lockPackage `json:"packages-dev"`
}

type lockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseLockFramework(lockPath string) string {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return ""
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return ""
	}

	packages := make(map[string]string)
	for _, pkg := range lock.Packages {
		packages[pkg.Name] = pkg.Version
	}
	for _, pkg := range lock.PackagesDev {
		packages[pkg.Name] = pkg.Version
	}

	return matchFramework(packages, "")
}
