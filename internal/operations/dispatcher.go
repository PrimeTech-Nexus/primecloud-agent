// Package operations provides the authoritative operation dispatcher, handler registry, idempotency tracking, and resource locking.
package operations

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

// Dispatcher executes typed operations with validation, locking, and idempotency guarantees.
type Dispatcher struct {
	registry    *Registry
	locks       *LockManager
	idempotency *IdempotencyTracker
	logger      *slog.Logger
}

// NewDispatcher constructs an operation Dispatcher.
func NewDispatcher(registry *Registry, locks *LockManager, idempotency *IdempotencyTracker, logger *slog.Logger) *Dispatcher {
	if registry == nil {
		registry = NewRegistry()
	}
	if locks == nil {
		locks = NewLockManager()
	}
	if idempotency == nil {
		idempotency = NewIdempotencyTracker(24 * time.Hour)
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Dispatcher{
		registry:    registry,
		locks:       locks,
		idempotency: idempotency,
		logger:      logger.With("component", "operation_dispatcher"),
	}
}

// Dispatch processes a typed OperationEnvelope and produces an OperationResponse.
func (d *Dispatcher) Dispatch(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
	if op == nil {
		return nil, fmt.Errorf("operation envelope cannot be nil")
	}

	d.logger.Info("dispatch_received",
		"operation_id", op.OperationId,
		"operation_type", op.OperationType,
		"resource_id", op.ResourceId,
	)

	// 1. Idempotency Check
	if cached, exists := d.idempotency.Get(op.OperationId); exists {
		d.logger.Info("dispatch_idempotent_skip",
			"operation_id", op.OperationId,
			"cached_status", cached.Status,
		)
		return cached, nil
	}

	// 2. Validate Operation Type
	handler, validator, exists := d.registry.Get(op.OperationType)
	if !exists {
		d.logger.Warn("dispatch_unknown_operation", "type", op.OperationType)
		resp := &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "FAILED",
			ErrorCode:       "UNKNOWN_OPERATION_TYPE",
			Message:         fmt.Sprintf("Operation type %s is not registered on this node", op.OperationType),
			CompletedAtUnix: time.Now().Unix(),
		}
		d.idempotency.Record(op.OperationId, resp)
		return resp, ErrUnknownOperation
	}

	// 3. Schema / Payload Validation
	if validator != nil {
		if err := validator(op.PayloadJson); err != nil {
			d.logger.Warn("dispatch_invalid_payload", "operation_id", op.OperationId, "error", err)
			resp := &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "INVALID_PAYLOAD_SCHEMA",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}
			d.idempotency.Record(op.OperationId, resp)
			return resp, err
		}
	}

	// 4. Resource Locking
	unlock, err := d.locks.AcquireLock(ctx, op.ResourceId)
	if err != nil {
		d.logger.Error("dispatch_lock_acquisition_failed", "resource_id", op.ResourceId, "error", err)
		resp := &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "FAILED",
			ErrorCode:       "LOCK_ACQUISITION_FAILED",
			Message:         err.Error(),
			CompletedAtUnix: time.Now().Unix(),
		}
		return resp, err
	}
	defer unlock()

	// 5. Execution Timeout and Context Handling
	opCtx := ctx
	var cancel context.CancelFunc
	if op.TimeoutSeconds > 0 {
		opCtx, cancel = context.WithTimeout(ctx, time.Duration(op.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	// Check cancellation before invoking handler
	select {
	case <-opCtx.Done():
		d.logger.Warn("dispatch_cancelled_before_execution", "operation_id", op.OperationId)
		resp := &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "CANCELLED",
			ErrorCode:       "OPERATION_CANCELLED",
			Message:         opCtx.Err().Error(),
			CompletedAtUnix: time.Now().Unix(),
		}
		d.idempotency.Record(op.OperationId, resp)
		return resp, opCtx.Err()
	default:
	}

	// 6. Execute Handler
	d.logger.Info("dispatch_executing_handler", "operation_id", op.OperationId, "type", op.OperationType)
	resp, err := handler(opCtx, op)
	if err != nil {
		d.logger.Error("dispatch_handler_failed", "operation_id", op.OperationId, "error", err)
		if resp == nil {
			resp = &pb.OperationResponse{
				OperationId:     op.OperationId,
				Status:          "FAILED",
				ErrorCode:       "EXECUTION_FAILED",
				Message:         err.Error(),
				CompletedAtUnix: time.Now().Unix(),
			}
		}
		d.idempotency.Record(op.OperationId, resp)
		return resp, err
	}

	if resp == nil {
		resp = &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}
	}

	d.idempotency.Record(op.OperationId, resp)
	d.logger.Info("dispatch_completed_successfully", "operation_id", op.OperationId, "status", resp.Status)
	return resp, nil
}
