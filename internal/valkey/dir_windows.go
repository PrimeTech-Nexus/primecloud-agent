//go:build windows

package valkey

import (
	"os"
)

// ensureValkeyDataDir ensures the host directory for /data exists on Windows.
func ensureValkeyDataDir(volumePath string) error {
	if err := os.MkdirAll(volumePath, 0700); err != nil {
		return err
	}
	return nil
}
