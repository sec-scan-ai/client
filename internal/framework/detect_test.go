package framework

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect_Frameworks(t *testing.T) {
	tests := []struct {
		name     string
		composer string
		want     string
	}{
		{
			name:     "OXID eShop 6.x",
			composer: `{"require": {"oxid-esales/oxideshop-ce": "v6.5.0"}}`,
			want:     "OXID eShop 6.x",
		},
		{
			name:     "OXID eShop 7.x with v prefix",
			composer: `{"require": {"oxid-esales/oxideshop-ce": "v7.0.0"}}`,
			want:     "OXID eShop 7.x",
		},
		{
			name:     "OXID eShop 7.x without v prefix",
			composer: `{"require": {"oxid-esales/oxideshop-ce": "7.1.0"}}`,
			want:     "OXID eShop 7.x",
		},
		{
			name:     "OXID eShop other package",
			composer: `{"require": {"oxid-esales/some-module": "^1.0"}}`,
			want:     "OXID eShop 6.x",
		},
		{
			name:     "Shopware 6 via core",
			composer: `{"require": {"shopware/core": "^6.4"}}`,
			want:     "Shopware 6",
		},
		{
			name:     "Shopware 6 via platform",
			composer: `{"require": {"shopware/platform": "^6.4"}}`,
			want:     "Shopware 6",
		},
		{
			name:     "Shopware 5",
			composer: `{"require": {"shopware/shopware": "^5.7"}}`,
			want:     "Shopware 5",
		},
		{
			name:     "Laravel",
			composer: `{"require": {"laravel/framework": "^10.0"}}`,
			want:     "Laravel",
		},
		{
			name:     "Symfony via framework-bundle",
			composer: `{"require": {"symfony/framework-bundle": "^6.0"}}`,
			want:     "Symfony",
		},
		{
			name:     "Symfony via symfony/symfony",
			composer: `{"require": {"symfony/symfony": "^6.0"}}`,
			want:     "Symfony",
		},
		{
			name:     "Magento",
			composer: `{"require": {"magento/framework": "^103.0"}}`,
			want:     "Magento",
		},
		{
			name:     "WordPress via woocommerce",
			composer: `{"require": {"woocommerce/woocommerce": "^8.0"}}`,
			want:     "WordPress/WooCommerce",
		},
		{
			name:     "WordPress via wordpress key",
			composer: `{"require": {"wordpress/core": "^6.0"}}`,
			want:     "WordPress/WooCommerce",
		},
		{
			name:     "Named project fallback",
			composer: `{"name": "my-vendor/my-app", "require": {"php": "^8.1"}}`,
			want:     "PHP project (my-vendor/my-app)",
		},
		{
			name:     "require-dev detection",
			composer: `{"require-dev": {"laravel/framework": "^10.0"}}`,
			want:     "Laravel",
		},
		{
			name:     "No match no name",
			composer: `{"require": {"php": "^8.1"}}`,
			want:     DefaultFramework,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeComposer(t, dir, tt.composer)

			got := Detect(dir)
			if got != tt.want {
				t.Errorf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetect_WalkUp(t *testing.T) {
	// composer.json is in parent directory
	root := t.TempDir()
	writeComposer(t, root, `{"require": {"laravel/framework": "^10.0"}}`)

	subDir := filepath.Join(root, "src", "app")
	os.MkdirAll(subDir, 0o755)

	got := Detect(subDir)
	if got != "Laravel" {
		t.Errorf("Detect() = %q, want %q (should find composer.json in parent)", got, "Laravel")
	}
}

func TestDetect_WalkDown(t *testing.T) {
	// composer.json is in a subdirectory (not current or parent)
	root := t.TempDir()
	subDir := filepath.Join(root, "packages", "app")
	os.MkdirAll(subDir, 0o755)
	writeComposer(t, subDir, `{"require": {"shopware/core": "^6.4"}}`)

	got := Detect(root)
	if got != "Shopware 6" {
		t.Errorf("Detect() = %q, want %q (should find composer.json in subdirectory)", got, "Shopware 6")
	}
}

func TestDetect_NoComposerJSON(t *testing.T) {
	dir := t.TempDir()

	got := Detect(dir)
	if got != DefaultFramework {
		t.Errorf("Detect() = %q, want %q", got, DefaultFramework)
	}
}

func TestDetect_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte("not json{{{"), 0o644)

	got := Detect(dir)
	if got != DefaultFramework {
		t.Errorf("Detect() = %q, want %q (invalid JSON should be skipped)", got, DefaultFramework)
	}
}

func writeComposer(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "composer.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write composer.json: %v", err)
	}
}
