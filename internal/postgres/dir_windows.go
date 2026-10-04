//go:build windows

package postgres

import (
	"os"
	"path/filepath"
)

// ensurePostgresDataDir ensures the host directory and pgdata subdirectory exist on Windows.
func ensurePostgresDataDir(volumePath string) error {
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return err
	}
	pgdata := filepath.Join(volumePath, "pgdata")
	if err := os.MkdirAll(pgdata, 0700); err != nil {
		return err
	}
	return nil
}
