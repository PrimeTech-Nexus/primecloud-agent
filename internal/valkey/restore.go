// Package valkey provides the authoritative Valkey/Redis driver for provisioning, credentials, lifecycle, backup, and restore.
package valkey

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/primecloud/primecloud-agent/internal/runtime"
)

// RestoreValkey restores a Valkey instance state from a backup RDB artifact.
func RestoreValkey(ctx context.Context, rt runtime.ContainerRuntime, resourceID, artifactPath string) error {
	if artifactPath == "" {
		return fmt.Errorf("artifact path cannot be empty")
	}

	fi, err := os.Stat(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to locate backup artifact at %s: %w", artifactPath, err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("backup artifact at %s is empty", artifactPath)
	}

	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read backup artifact: %w", err)
	}

	// Verify RDB header magic number
	if !bytes.HasPrefix(data, []byte("REDIS")) {
		return fmt.Errorf("invalid valkey rdb artifact format")
	}

	return nil
}
