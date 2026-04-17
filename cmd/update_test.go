package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/sec-scan-ai/client/internal/updatecheck"
)

func TestAssetName(t *testing.T) {
	name := updatecheck.AssetName()

	expected := "sec-scan-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		expected += ".exe"
	}

	if name != expected {
		t.Errorf("AssetName() = %q, want %q", name, expected)
	}
}

func TestAssetName_ContainsOSAndArch(t *testing.T) {
	name := updatecheck.AssetName()

	if !strings.Contains(name, runtime.GOOS) {
		t.Errorf("AssetName() = %q, should contain OS %q", name, runtime.GOOS)
	}
	if !strings.Contains(name, runtime.GOARCH) {
		t.Errorf("AssetName() = %q, should contain arch %q", name, runtime.GOARCH)
	}
}
