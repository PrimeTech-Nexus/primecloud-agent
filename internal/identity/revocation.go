// Package identity manages agent x509 certificates, TLS identity files, rotation, and revocation.
package identity

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
)

// ErrAgentRevoked is returned when the agent has been revoked.
var ErrAgentRevoked = errors.New("agent has been revoked by control plane")

// RevocationHandler monitors error streams and control signals for agent revocation.
type RevocationHandler struct {
	revoked  atomic.Bool
	logger   *slog.Logger
	onRevoke func()
}

// NewRevocationHandler constructs a RevocationHandler with an optional callback on revocation.
func NewRevocationHandler(logger *slog.Logger, onRevoke func()) *RevocationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &RevocationHandler{
		logger:   logger.With("component", "revocation_handler"),
		onRevoke: onRevoke,
	}
}

// CheckRevocationError examines an error or response message to see if it indicates node revocation.
func (h *RevocationHandler) CheckRevocationError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToUpper(err.Error())
	if strings.Contains(errStr, "AGENT_REVOKED") ||
		strings.Contains(errStr, "CERTIFICATE_REVOKED") ||
		strings.Contains(errStr, "NODE_UNAUTHORIZED") ||
		strings.Contains(errStr, "REVOKED") {
		h.TriggerRevocation(err.Error())
		return true
	}

	return false
}

// TriggerRevocation marks the agent as revoked and invokes the shutdown callback.
func (h *RevocationHandler) TriggerRevocation(reason string) {
	if h.revoked.CompareAndSwap(false, true) {
		h.logger.Error("agent_identity_revoked_by_control_plane", "reason", reason)
		if h.onRevoke != nil {
			h.onRevoke()
		}
	}
}

// IsRevoked returns true if the agent identity has been marked revoked.
func (h *RevocationHandler) IsRevoked() bool {
	return h.revoked.Load()
}

// EnsureNotRevoked returns ErrAgentRevoked if the agent is marked revoked.
func (h *RevocationHandler) EnsureNotRevoked() error {
	if h.IsRevoked() {
		return fmt.Errorf("%w: cannot execute operations; node has been revoked", ErrAgentRevoked)
	}
	return nil
}
