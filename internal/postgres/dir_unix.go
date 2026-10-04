//go:build !windows

package postgres

import (
	"os"
	"syscall"
)

// ensurePostgresDataDir ensures the host directory and pgdata subdirectory exist
// and are owned by UID 999:999 (postgres in postgres:16-alpine) with 0700 permissions.
func ensurePostgresDataDir(volumePath string) error {
	// 1. Ensure volume root directory exists
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return err
	}
	// Best-effort chown volume root to postgres:postgres (999:999)
	_ = syscall.Chown(volumePath, 999, 999)
	_ = os.Chmod(volumePath, 0700)

	// 2. Ensure pgdata subdirectory exists
	pgdata := volumePath + "/pgdata"
	if err := os.MkdirAll(pgdata, 0700); err != nil {
		return err
	}
	// Best-effort chown pgdata to postgres:postgres (999:999)
	_ = syscall.Chown(pgdata, 999, 999)
	_ = os.Chmod(pgdata, 0700)

	return nil
}
