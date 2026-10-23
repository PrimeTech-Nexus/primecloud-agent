//go:build windows

package mongodb

import (
	"os"
	"path/filepath"
)

// ensureMongoDBDataDir ensures the host data directory and keyfile exist on Windows.
func ensureMongoDBDataDir(volumePath, keyfileContent string) (string, string, error) {
	dataDir := filepath.Join(volumePath, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", "", err
	}
	keyfilePath := filepath.Join(volumePath, "mongo-keyfile")
	if _, err := os.Stat(keyfilePath); os.IsNotExist(err) {
		if err := os.WriteFile(keyfilePath, []byte(keyfileContent), 0600); err != nil {
			return "", "", err
		}
	}
	return dataDir, keyfilePath, nil
}
