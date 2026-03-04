//go:build windows

package collector

import "os"

func getInode(path string) (inode, error) {
	// Windows lacks Unix-style inodes. Use a zero inode to skip loop detection.
	// Symlink loops on Windows are rare and handled by max depth in practice.
	_, err := os.Stat(path)
	if err != nil {
		return inode{}, err
	}
	return inode{}, nil
}
