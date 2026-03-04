package setup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const configDirName = ".sec-scan"
const envFileName = ".env"

// ConfigDir returns the path to ~/.sec-scan/.
func ConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, configDirName)
}

// EnvFile returns the path to ~/.sec-scan/.env.
func EnvFile() string {
	dir := ConfigDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, envFileName)
}

// EnsureConfigDir checks if ~/.sec-scan/ exists. If not, prompts the user
// to create it and set up an API token. Returns true if setup was performed
// or the directory already existed.
func EnsureConfigDir() {
	dir := ConfigDir()
	if dir == "" {
		return
	}

	// Already exists - nothing to do
	if _, err := os.Stat(dir); err == nil {
		return
	}

	// Check if we're in an interactive terminal
	if !isTerminal() {
		return
	}

	fmt.Println("sec-scan: first-time setup")
	fmt.Println()
	fmt.Printf("  Config directory %s does not exist.\n", dir)
	fmt.Println("  This is where your API token and settings are stored.")
	fmt.Println()

	if !promptYesNo("Create it now?") {
		fmt.Println("Skipped. You can pass --token on the command line instead.")
		return
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", dir, err)
		return
	}

	fmt.Println()
	if promptYesNo("Do you already have an API token?") {
		fmt.Println()
		token := promptString("Enter your API token (sc_...)")
		if token == "" {
			fmt.Println("No token entered. You can add it later to " + EnvFile())
			writeEnvFile("")
			return
		}

		writeEnvFile(token)
		fmt.Println()
		fmt.Printf("Config saved to %s\n", EnvFile())
	} else {
		fmt.Println()
		fmt.Println("  You can get a token from your sec-scan server's settings page.")
		fmt.Printf("  Once you have one, add it to %s like this:\n", EnvFile())
		fmt.Println()
		fmt.Println("    SEC_SCAN_TOKEN=sc_your_token_here")
		fmt.Println()
		writeEnvFile("")
	}
}

func writeEnvFile(token string) {
	content := ""
	if token != "" {
		content = fmt.Sprintf("SEC_SCAN_TOKEN=%s\n", token)
	}

	envPath := EnvFile()
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", envPath, err)
	}
}

func promptYesNo(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [Y/n] ", question)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "" || answer == "y" || answer == "yes"
}

func promptString(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", prompt)
	answer, _ := reader.ReadString('\n')
	return strings.TrimSpace(answer)
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
