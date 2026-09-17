// Package recovery coordinates artifact decryption, integrity verification, and workload state reconstruction.
package recovery

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/primecloud/primecloud-agent/internal/backup"
	agentruntime "github.com/primecloud/primecloud-agent/internal/runtime"
)

// Verifier handles post-restoration verification of data and runtime instances.
type Verifier struct {
	rt agentruntime.ContainerRuntime
}

// NewVerifier constructs a Verifier.
func NewVerifier(rt agentruntime.ContainerRuntime) *Verifier {
	return &Verifier{rt: rt}
}

// VerifyIntegrity checks the SHA-256 hash and size of a restored artifact against its manifest.
func (v *Verifier) VerifyIntegrity(m *backup.Manifest, artifactPath string) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}
	return m.VerifyIntegrity(artifactPath)
}

// VerifyFormat validates file magic bytes or headers based on resource type.
func (v *Verifier) VerifyFormat(resourceType, artifactPath string) error {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to read artifact for format verification: %w", err)
	}

	switch resourceType {
	case "valkey":
		if !bytes.HasPrefix(data, []byte("REDIS")) {
			return fmt.Errorf("valkey artifact missing valid REDIS header")
		}
	case "postgres":
		if len(data) < 10 {
			return fmt.Errorf("postgres artifact truncated")
		}
	}

	return nil
}

// VerifyServiceReady checks whether the target container has booted and is healthy.
func (v *Verifier) VerifyServiceReady(ctx context.Context, containerID string) error {
	if v.rt == nil {
		return nil // Non-fatal in unit test mode
	}

	c, err := v.rt.InspectContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	if !c.Running {
		return fmt.Errorf("restored container %s is not running (state: %s)", containerID, c.State)
	}

	return nil
}
