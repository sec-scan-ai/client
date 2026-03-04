package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/sec-scan-ai/client/cmd"
	"github.com/sec-scan-ai/client/internal/setup"
)

func main() {
	// First-run setup: create ~/.sec-scan/ and prompt for token if needed
	setup.EnsureConfigDir()

	// Load env files. Later files don't override earlier ones in godotenv,
	// so cwd .env takes precedence over ~/.sec-scan/.env.
	godotenv.Load()               // cwd/.env (highest priority)
	if f := setup.EnvFile(); f != "" {
		godotenv.Load(f)           // ~/.sec-scan/.env (fallback)
	}

	rootCmd := cmd.NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
