package collector

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	ChunkSize    = 400_000
	ChunkOverlap = 20_000
)

// PHPFile represents a collected PHP file (or chunk of one) with its metadata.
type PHPFile struct {
	AbsPath     string
	RelPath     string // includes " [1/3]" suffix for chunks
	Checksum    string
	Size        int64
	ChunkOffset int // 0 for non-chunked
	ChunkLen    int // 0 for non-chunked (means full file)
}

// CollectPHPFiles walks the target path and returns all .php files.
// Excludes are matched case-insensitively against relative paths from the scan root.
// For example, "vendor" only excludes <root>/vendor, not <root>/src/vendor.
// Use "src/vendor" to exclude <root>/src/vendor specifically.
// If followSymlinks is true, symlinks are followed with loop detection.
func CollectPHPFiles(target string, excludes []string, followSymlinks bool) ([]PHPFile, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", target, err)
	}

	if !info.IsDir() {
		if !isPHP(target) {
			return nil, fmt.Errorf("%s is not a .php file", target)
		}
		chunks, err := collectFile(target, target)
		if err != nil {
			return nil, err
		}
		return chunks, nil
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve path %s: %w", target, err)
	}

	excludeLower := make([]string, len(excludes))
	for i, e := range excludes {
		excludeLower[i] = strings.ToLower(strings.TrimRight(e, "/\\"))
	}

	var files []PHPFile
	visited := make(map[inode]bool)

	if followSymlinks {
		err = walkFollowSymlinks(absTarget, absTarget, excludeLower, visited, &files)
	} else {
		err = filepath.WalkDir(absTarget, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() && shouldExclude(path, absTarget, excludeLower) {
				return filepath.SkipDir
			}
			if d.IsDir() || !isPHP(path) {
				return nil
			}
			chunks, err := collectFile(path, absTarget)
			if err != nil {
				return nil // skip unreadable files
			}
			files = append(files, chunks...)
			return nil
		})
	}

	return files, err
}

// sanitizeUTF8 replaces invalid UTF-8 bytes with the Unicode replacement
// character (U+FFFD), matching what Go's json.Marshal does during encoding.
// This ensures checksums computed from the sanitized string match what the
// server sees after JSON decoding.
func sanitizeUTF8(data []byte) string {
	return strings.ToValidUTF8(string(data), string(utf8.RuneError))
}

// ReadContent reads file content for sending to the server.
// For non-chunked files (offset=0, length=0), reads the full file.
// For chunks, reads the specified byte range.
// Invalid UTF-8 bytes are replaced with U+FFFD to match JSON encoding behavior.
func ReadContent(path string, offset, length int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if offset > 0 || length > 0 {
		end := offset + length
		if end > len(data) {
			end = len(data)
		}
		data = data[offset:end]
	}
	return sanitizeUTF8(data), nil
}

// fileChecksum computes the SHA256 hex digest of content as it would be sent
// to the server (UTF-8 sanitized). This ensures the checksum matches what the
// server computes from the received content.
func fileChecksum(content string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
}

type inode struct {
	dev uint64
	ino uint64
}

func walkFollowSymlinks(root, base string, excludes []string, visited map[inode]bool, files *[]PHPFile) error {
	ino, err := getInode(root)
	if err != nil {
		return nil // skip inaccessible
	}
	// On non-Unix systems (inode 0,0), skip loop detection
	if ino.ino != 0 || ino.dev != 0 {
		if visited[ino] {
			return nil // symlink loop - skip
		}
		visited[ino] = true
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil // skip unreadable dirs
	}

	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())

		// Resolve symlinks
		info, err := os.Stat(path)
		if err != nil {
			continue // skip broken symlinks
		}

		if info.IsDir() {
			if shouldExclude(path, base, excludes) {
				continue
			}
			walkFollowSymlinks(path, base, excludes, visited, files)
			continue
		}

		if !isPHP(entry.Name()) {
			continue
		}

		chunks, err := collectFile(path, base)
		if err != nil {
			continue // skip unreadable files
		}
		*files = append(*files, chunks...)
	}

	return nil
}

func collectFile(path, base string) ([]PHPFile, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	relPath, err := filepath.Rel(base, absPath)
	if err != nil {
		relPath = filepath.Base(absPath)
	}
	relPath = filepath.ToSlash(relPath)

	// Small file - single entry, no chunking
	if len(data) <= ChunkSize {
		content := sanitizeUTF8(data)
		return []PHPFile{{
			AbsPath:  absPath,
			RelPath:  relPath,
			Checksum: fileChecksum(content),
			Size:     info.Size(),
		}}, nil
	}

	// Large file - split into overlapping chunks
	var chunks []PHPFile
	step := ChunkSize - ChunkOverlap
	totalChunks := (len(data)-1)/step + 1

	for i := 0; i < totalChunks; i++ {
		offset := i * step
		end := offset + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunkContent := sanitizeUTF8(data[offset:end])
		chunks = append(chunks, PHPFile{
			AbsPath:     absPath,
			RelPath:     fmt.Sprintf("%s [%d/%d]", relPath, i+1, totalChunks),
			Checksum:    fileChecksum(chunkContent),
			Size:        info.Size(),
			ChunkOffset: offset,
			ChunkLen:    end - offset,
		})
	}

	return chunks, nil
}

func isPHP(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".php")
}

func shouldExclude(dirPath, base string, excludes []string) bool {
	rel, err := filepath.Rel(base, dirPath)
	if err != nil {
		return false
	}
	relLower := strings.ToLower(filepath.ToSlash(rel))

	for _, e := range excludes {
		if relLower == e {
			return true
		}
	}
	return false
}
