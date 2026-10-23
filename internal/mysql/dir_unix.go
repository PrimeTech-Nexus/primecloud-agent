//go:build !windows

package mysql

import (
	"os"
	"syscall"
)

// ensureMySQLDataDir ensures the host directory for /var/lib/mysql exists
// and is owned by UID 999:999 (mysql user inside official mysql:8.0 / mysql:8.4 images) with 0700 permissions.
func ensureMySQLDataDir(volumePath string) error {
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return err
	}
	_ = syscall.Chown(volumePath, 999, 999)
	_ = os.Chmod(volumePath, 0700)
	return nil
}
