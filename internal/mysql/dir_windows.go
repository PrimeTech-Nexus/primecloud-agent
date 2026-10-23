//go:build windows

package mysql

import (
	"os"
)

// ensureMySQLDataDir ensures the host directory exists on Windows.
func ensureMySQLDataDir(volumePath string) error {
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return err
	}
	return nil
}
