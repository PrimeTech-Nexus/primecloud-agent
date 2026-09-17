// Package operations provides the authoritative operation dispatcher, handler registry, idempotency tracking, and resource locking.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

var (
	ErrUnknownOperation = errors.New("unknown or unsupported operation type")
	ErrInvalidPayload   = errors.New("invalid operation payload schema")
)

// HandlerFunc defines the standard signature for typed operation handlers.
type HandlerFunc func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error)

// ValidatorFunc defines optional schema validation on the JSON payload.
type ValidatorFunc func(payloadJSON string) error

// Registry maintains the dictionary of authorized, typed operations.
type Registry struct {
	mu         sync.RWMutex
	handlers   map[string]HandlerFunc
	validators map[string]ValidatorFunc
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		handlers:   make(map[string]HandlerFunc),
		validators: make(map[string]ValidatorFunc),
	}
}

// Register adds an operation type with its handler and optional validator.
func (r *Registry) Register(opType string, handler HandlerFunc, validator ValidatorFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.handlers[opType] = handler
	if validator != nil {
		r.validators[opType] = validator
	} else {
		// Default JSON validator
		r.validators[opType] = DefaultJSONValidator
	}
}

// Get retrieves the handler and validator for a given operation type.
func (r *Registry) Get(opType string) (HandlerFunc, ValidatorFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	h, exists := r.handlers[opType]
	if !exists {
		return nil, nil, false
	}
	v := r.validators[opType]
	return h, v, true
}

// SupportedTypes returns the list of registered operation types.
func (r *Registry) SupportedTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.handlers))
	for k := range r.handlers {
		types = append(types, k)
	}
	return types
}

// DefaultJSONValidator validates that the payload is well-formed JSON.
func DefaultJSONValidator(payloadJSON string) error {
	if payloadJSON == "" {
		return nil
	}
	var js json.RawMessage
	if err := json.Unmarshal([]byte(payloadJSON), &js); err != nil {
		return fmt.Errorf("%w: payload is not valid JSON: %v", ErrInvalidPayload, err)
	}
	return nil
}
