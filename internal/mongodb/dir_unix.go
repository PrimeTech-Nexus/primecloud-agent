//go:build !windows

package mongodb

import (
	"os"
	"path/filepath"
	"syscall"
)

// ensureMongoDBDataDir ensures the host data directory and keyfile exist
// with UID 999:999 ownership and strict permissions (0700 for data, 0600 for keyfile).
func ensureMongoDBDataDir(volumePath, keyfileContent string) (string, string, error) {
	dataDir := filepath.Join(volumePath, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", "", err
	}
	_ = syscall.Chown(volumePath, 999, 999)
	_ = syscall.Chown(dataDir, 999, 999)
	_ = os.Chmod(dataDir, 0700)

	keyfilePath := filepath.Join(volumePath, "mongo-keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		if err := os.WriteFile(keyfilePath, []byte(keyfileContent), 0600); err != nil {
			return "", "", err
		}
	}
	_ = syscall.Chown(keyfilePath, 999, 999)
	_ = os.Chmod(keyfilePath, 0600)

	return dataDir, keyfilePath, nil
}
