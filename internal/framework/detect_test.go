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
			name:     "JTL-Shop 5 via jtl-shop",
			composer: `{"require": {"jtl-shop/shop5-core": "^5.0"}}`,
			want:     "JTL-Shop 5",
		},
		{
			name:     "JTL-Shop 5 via jtl prefix",
			composer: `{"require": {"jtl/connector-core": "^5.0"}}`,
			want:     "JTL-Shop 5",
		},
		{
			name:     "PrestaShop",
			composer: `{"require": {"prestashop/prestashop": "^8.0"}}`,
			want:     "PrestaShop",
		},
		{
			name:     "Sylius",
			composer: `{"require": {"sylius/sylius": "^1.12"}}`,
			want:     "Sylius",
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

func TestDetect_ComposerLock(t *testing.T) {
	t.Run("lock preferred over json", func(t *testing.T) {
		dir := t.TempDir()
		writeComposer(t, dir, `{"require": {"laravel/framework": "^10.0"}}`)
		writeComposerLock(t, dir, `{"packages": [{"name": "shopware/core", "version": "v6.5.0"}]}`)

		got := Detect(dir)
		if got != "Shopware 6" {
			t.Errorf("Detect() = %q, want %q (lock should take precedence)", got, "Shopware 6")
		}
	})

	t.Run("lock with no match falls back to json", func(t *testing.T) {
		dir := t.TempDir()
		writeComposer(t, dir, `{"require": {"laravel/framework": "^10.0"}}`)
		writeComposerLock(t, dir, `{"packages": [{"name": "php", "version": "8.2.0"}]}`)

		got := Detect(dir)
		if got != "Laravel" {
			t.Errorf("Detect() = %q, want %q (should fall back to composer.json)", got, "Laravel")
		}
	})

	t.Run("invalid lock json falls back to json", func(t *testing.T) {
		dir := t.TempDir()
		writeComposer(t, dir, `{"require": {"laravel/framework": "^10.0"}}`)
		os.WriteFile(filepath.Join(dir, "composer.lock"), []byte("not json{{{"), 0o644)

		got := Detect(dir)
		if got != "Laravel" {
			t.Errorf("Detect() = %q, want %q (invalid lock should fall back to json)", got, "Laravel")
		}
	})

	t.Run("lock packages-dev detection", func(t *testing.T) {
		dir := t.TempDir()
		writeComposerLock(t, dir, `{"packages": [], "packages-dev": [{"name": "laravel/framework", "version": "v10.0.0"}]}`)

		got := Detect(dir)
		if got != "Laravel" {
			t.Errorf("Detect() = %q, want %q", got, "Laravel")
		}
	})

	t.Run("lock with exact version for OXID 7", func(t *testing.T) {
		dir := t.TempDir()
		writeComposerLock(t, dir, `{"packages": [{"name": "oxid-esales/oxideshop-ce", "version": "v7.0.1"}]}`)

		got := Detect(dir)
		if got != "OXID eShop 7.x" {
			t.Errorf("Detect() = %q, want %q", got, "OXID eShop 7.x")
		}
	})
}

func TestDetect_WalkUp(t *testing.T) {
	t.Run("finds composer.json in parent", func(t *testing.T) {
		root := t.TempDir()
		writeComposer(t, root, `{"require": {"laravel/framework": "^10.0"}}`)

		subDir := filepath.Join(root, "src", "app")
		os.MkdirAll(subDir, 0o755)

		got := Detect(subDir)
		if got != "Laravel" {
			t.Errorf("Detect() = %q, want %q (should find composer.json in parent)", got, "Laravel")
		}
	})

	t.Run("finds composer.lock in parent", func(t *testing.T) {
		root := t.TempDir()
		writeComposerLock(t, root, `{"packages": [{"name": "shopware/core", "version": "v6.5.0"}]}`)

		subDir := filepath.Join(root, "public")
		os.MkdirAll(subDir, 0o755)

		got := Detect(subDir)
		if got != "Shopware 6" {
			t.Errorf("Detect() = %q, want %q (should find composer.lock in parent)", got, "Shopware 6")
		}
	})

	t.Run("scan dir takes precedence over parent", func(t *testing.T) {
		root := t.TempDir()
		writeComposer(t, root, `{"require": {"laravel/framework": "^10.0"}}`)

		subDir := filepath.Join(root, "subproject")
		os.MkdirAll(subDir, 0o755)
		writeComposer(t, subDir, `{"require": {"shopware/core": "^6.4"}}`)

		got := Detect(subDir)
		if got != "Shopware 6" {
			t.Errorf("Detect() = %q, want %q (scan dir should take precedence)", got, "Shopware 6")
		}
	})
}

func TestDetect_NoWalkDown(t *testing.T) {
	// composer.json only in a subdirectory - should NOT be found
	root := t.TempDir()
	subDir := filepath.Join(root, "packages", "app")
	os.MkdirAll(subDir, 0o755)
	writeComposer(t, subDir, `{"require": {"shopware/core": "^6.4"}}`)

	got := Detect(root)
	if got != DefaultFramework {
		t.Errorf("Detect() = %q, want %q (should not walk down into subdirectories)", got, DefaultFramework)
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

func writeComposerLock(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write composer.lock: %v", err)
	}
}
