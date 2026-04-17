package ignore

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const checksumLen = 64 // SHA256 hex length

// Load reads an ignore file and returns a set of valid SHA256 checksums
// plus any per-line warnings (so the caller can decide whether to print
// them based on quiet/verbosity settings). Lines can contain an optional
// inline comment after the checksum (separated by whitespace or #).
// Returns an empty map if the file does not exist.
func Load(path string) (map[string]bool, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	result := make(map[string]bool)
	var warnings []string
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
			warnings = append(warnings, fmt.Sprintf("ignore file line %d: expected %d hex chars, got %d: %q", lineNum, checksumLen, len(field), field))
			continue
		}

		if _, err := hex.DecodeString(field); err != nil {
			warnings = append(warnings, fmt.Sprintf("ignore file line %d: invalid hex: %q", lineNum, field))
			continue
		}

		result[field] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, warnings, fmt.Errorf("reading ignore file: %w", err)
	}

	return result, warnings, nil
}
