package collector

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const MaxFileSize = 500_000

// PHPFile represents a collected PHP file with its metadata.
type PHPFile struct {
	AbsPath  string
	RelPath  string
	Checksum string
	Size     int64
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
		f, err := collectFile(target, target)
		if err != nil {
			return nil, err
		}
		return []PHPFile{f}, nil
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
			f, err := collectFile(path, absTarget)
			if err != nil {
				return nil // skip unreadable files
			}
			files = append(files, f)
			return nil
		})
	}

	return files, err
}

// ReadContent reads file content, truncating at MaxFileSize.
func ReadContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) > MaxFileSize {
		return string(data[:MaxFileSize]) + "\n... [truncated]", nil
	}
	return string(data), nil
}

// FileChecksum computes the SHA256 hex digest of a file's contents.
func FileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
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

		f, err := collectFile(path, base)
		if err != nil {
			continue // skip unreadable files
		}
		*files = append(*files, f)
	}

	return nil
}

func collectFile(path, base string) (PHPFile, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return PHPFile{}, err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return PHPFile{}, err
	}

	checksum, err := FileChecksum(absPath)
	if err != nil {
		return PHPFile{}, err
	}

	relPath, err := filepath.Rel(base, absPath)
	if err != nil {
		relPath = filepath.Base(absPath)
	}

	return PHPFile{
		AbsPath:  absPath,
		RelPath:  filepath.ToSlash(relPath),
		Checksum: checksum,
		Size:     info.Size(),
	}, nil
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
