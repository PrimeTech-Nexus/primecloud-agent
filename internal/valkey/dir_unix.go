//go:build !windows

package valkey

import (
	"os"
	"syscall"
)

// ensureValkeyDataDir ensures the host directory for /data exists
// and is owned by UID 999:999 (valkey user inside official valkey images) with 0700 permissions.
func ensureValkeyDataDir(volumePath string) error {
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return err
	}
	_ = syscall.Chown(volumePath, 999, 999)
	_ = os.Chmod(volumePath, 0700)
	return nil
}
