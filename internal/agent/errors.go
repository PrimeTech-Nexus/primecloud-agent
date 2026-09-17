// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"errors"
	"fmt"
)

// Sentinel domain errors for PrimeCloud Agent.
var (
	ErrInvalidConfig      = errors.New("invalid agent configuration")
	ErrVaultUnavailable   = errors.New("vault service is unavailable")
	ErrBootstrapFailed    = errors.New("vault bootstrap failed")
	ErrRegistrationFailed = errors.New("agent registration with control plane failed")
	ErrCertificateExpired = errors.New("agent identity certificate has expired")
	ErrAgentRevoked       = errors.New("agent has been revoked by control plane")
	ErrOperationRejected  = errors.New("operation rejected by policy or schema")
	ErrLockConflict       = errors.New("resource lock conflict")
	ErrDegradedNode       = errors.New("node is in a degraded or critical state")
)

// AgentError represents a structured, domain-specific error.
type AgentError struct {
	Code    string
	Message string
	Err     error
}

// Error formats the AgentError for output.
func (e *AgentError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap supports errors.Unwrap chain inspection.
func (e *AgentError) Unwrap() error {
	return e.Err
}

// NewAgentError constructs an AgentError instance.
func NewAgentError(code, message string, err error) *AgentError {
	return &AgentError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
