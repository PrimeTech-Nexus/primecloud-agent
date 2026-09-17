package operations_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/operations"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

func TestDispatcher_ExecutionAndIdempotency(t *testing.T) {
	reg := operations.NewRegistry()
	var executedCount atomic.Int32

	reg.Register("deploy_application", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		executedCount.Add(1)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			ResultJson:      `{"deployed": true}`,
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, operations.DefaultJSONValidator)

	dispatcher := operations.NewDispatcher(reg, nil, nil, nil)
	ctx := context.Background()

	op := &pb.OperationEnvelope{
		OperationId:    "op-101",
		OperationType:  "deploy_application",
		ResourceId:     "res-app-1",
		PayloadJson:    `{"image": "nginx:alpine"}`,
		TimeoutSeconds: 5,
	}

	// 1. First execution
	resp1, err := dispatcher.Dispatch(ctx, op)
	if err != nil {
		t.Fatalf("First dispatch failed: %v", err)
	}
	if resp1.Status != "SUCCEEDED" {
		t.Errorf("Expected SUCCEEDED, got %s", resp1.Status)
	}
	if executedCount.Load() != 1 {
		t.Errorf("Expected handler executed once, got %d", executedCount.Load())
	}

	// 2. Duplicate operation ID (idempotent skip)
	resp2, err := dispatcher.Dispatch(ctx, op)
	if err != nil {
		t.Fatalf("Second dispatch failed: %v", err)
	}
	if resp2.Status != "SUCCEEDED" {
		t.Errorf("Expected SUCCEEDED on duplicate, got %s", resp2.Status)
	}
	if executedCount.Load() != 1 {
		t.Errorf("Handler should NOT re-execute for duplicate operation_id; count=%d", executedCount.Load())
	}
}

func TestDispatcher_UnknownOperationRejected(t *testing.T) {
	dispatcher := operations.NewDispatcher(nil, nil, nil, nil)
	ctx := context.Background()

	op := &pb.OperationEnvelope{
		OperationId:   "op-102",
		OperationType: "unsupported_legacy_op",
		PayloadJson:   `{}`,
	}

	resp, err := dispatcher.Dispatch(ctx, op)
	if err == nil || !errors.Is(err, operations.ErrUnknownOperation) {
		t.Fatalf("Expected ErrUnknownOperation, got err=%v", err)
	}
	if resp.Status != "FAILED" || resp.ErrorCode != "UNKNOWN_OPERATION_TYPE" {
		t.Errorf("Unexpected response for unknown op: %+v", resp)
	}
}

func TestDispatcher_InvalidPayloadRejected(t *testing.T) {
	reg := operations.NewRegistry()
	reg.Register("custom_op", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		return &pb.OperationResponse{Status: "SUCCEEDED"}, nil
	}, operations.DefaultJSONValidator)

	dispatcher := operations.NewDispatcher(reg, nil, nil, nil)
	ctx := context.Background()

	op := &pb.OperationEnvelope{
		OperationId:   "op-103",
		OperationType: "custom_op",
		PayloadJson:   `{invalid-json-data`,
	}

	resp, err := dispatcher.Dispatch(ctx, op)
	if err == nil || !errors.Is(err, operations.ErrInvalidPayload) {
		t.Fatalf("Expected ErrInvalidPayload, got err=%v", err)
	}
	if resp.Status != "FAILED" || resp.ErrorCode != "INVALID_PAYLOAD_SCHEMA" {
		t.Errorf("Unexpected response for invalid payload: %+v", resp)
	}
}

func TestDispatcher_ResourceLocking(t *testing.T) {
	reg := operations.NewRegistry()
	var inFlight atomic.Int32
	var maxConcurrent atomic.Int32

	reg.Register("slow_op", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		current := inFlight.Add(1)
		for {
			max := maxConcurrent.Load()
			if current <= max || maxConcurrent.CompareAndSwap(max, current) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inFlight.Add(-1)
		return &pb.OperationResponse{Status: "SUCCEEDED"}, nil
	}, nil)

	dispatcher := operations.NewDispatcher(reg, nil, nil, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	// Run 2 operations on SAME resource concurrently
	for i := 0; i < 2; i++ {
		wg.Add(1)
		opID := "op-lock-" + string(rune('a'+i))
		go func(id string) {
			defer wg.Done()
			_, _ = dispatcher.Dispatch(ctx, &pb.OperationEnvelope{
				OperationId:   id,
				OperationType: "slow_op",
				ResourceId:    "shared-resource-postgres",
				PayloadJson:   `{}`,
			})
		}(opID)
	}
	wg.Wait()

	if maxConcurrent.Load() > 1 {
		t.Errorf("Lock failed to prevent concurrent execution on same resource: max=%d", maxConcurrent.Load())
	}
}

func TestDispatcher_Cancellation(t *testing.T) {
	reg := operations.NewRegistry()
	started := make(chan struct{})

	reg.Register("blocking_op", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)

	dispatcher := operations.NewDispatcher(reg, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := dispatcher.Dispatch(ctx, &pb.OperationEnvelope{
			OperationId:   "op-cancel-1",
			OperationType: "blocking_op",
			ResourceId:    "cancel-res",
			PayloadJson:   `{}`,
		})
		errCh <- err
	}()

	<-started
	cancel() // Trigger cancellation

	select {
	case err := <-errCh:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Operation did not abort on context cancellation")
	}
}
