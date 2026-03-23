package cmd

import (
	"runtime"
	"strings"
	"testing"
)

func TestBinaryName(t *testing.T) {
	name := binaryName()

	expected := "sec-scan-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		expected += ".exe"
	}

	if name != expected {
		t.Errorf("binaryName() = %q, want %q", name, expected)
	}
}

func TestBinaryName_ContainsOSAndArch(t *testing.T) {
	name := binaryName()

	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("binaryName() = %q, should contain OS %q", name, runtime.GOOS)
	}
	if !strings.Contains(name, runtime.GOARCH) {
		t.Errorf("binaryName() = %q, should contain arch %q", name, runtime.GOARCH)
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.1.0", -1},
		{"1.1.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.2.3", "1.3.0", -1},
		{"0.1.0", "0.2.0", -1},
		{"1.10.0", "1.9.0", 1},
		// Pre-release suffixes stripped
		{"1.0.0-rc1", "1.0.0", 0},
		{"1.0.0-beta", "1.0.1", -1},
		// Partial versions (missing patch)
		{"1.0", "1.0.0", 0},
		{"1", "1.0.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got, err := compareSemver(tt.a, tt.b)
			if err != nil {
				t.Fatalf("compareSemver(%q, %q) error: %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Errorf("compareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareSemver_InvalidVersion(t *testing.T) {
	_, err := compareSemver("not.a.version", "1.0.0")
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestCompareSemver_DevVersion(t *testing.T) {
	// "dev" is the default version when built without ldflags
	_, err := compareSemver("dev", "1.0.0")
	if err == nil {
		t.Error("expected error for dev version")
	}
}
