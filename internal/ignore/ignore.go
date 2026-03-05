package ignore

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const checksumLen = 64 // SHA256 hex length

// Load reads an ignore file and returns a set of valid SHA256 checksums.
// Lines can contain an optional inline comment after the checksum (separated by whitespace or #).
// Returns an empty map if the file does not exist.
func Load(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	defer f.Close()

	result := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract checksum: split on first whitespace or #
		field := line
		if idx := strings.IndexAny(line, " \t#"); idx != -1 {
			field = line[:idx]
		}

		field = strings.ToLower(field)

		if len(field) != checksumLen {
			fmt.Fprintf(os.Stderr, "Warning: ignore file line %d: expected %d hex chars, got %d: %q\n", lineNum, checksumLen, len(field), field)
			continue
		}

		if _, err := hex.DecodeString(field); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: ignore file line %d: invalid hex: %q\n", lineNum, field)
			continue
		}

		result[field] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading ignore file: %w", err)
	}

	return result, nil
}
