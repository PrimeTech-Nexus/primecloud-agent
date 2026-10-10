//go:build !windows

package postgres

import (
	"os"
	"syscall"
)

func getAvailableDiskBytes(path string) (int64, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return 0, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}
