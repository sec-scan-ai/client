//go:build !windows

package collector

import (
	"os"
	"syscall"
)

func getInode(path string) (inode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return inode{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return inode{}, nil
	}
	return inode{dev: uint64(stat.Dev), ino: stat.Ino}, nil
}
