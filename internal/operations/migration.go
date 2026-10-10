// Package operations provides the authoritative operation dispatcher, handler registry, idempotency tracking, and resource locking.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/postgres"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

// RegisterMigrationOperations registers all 6 canonical PostgreSQL migration operations defined in migration-contract-v1.
// 1. prepare_migration_target
// 2. create_migration_snapshot
// 3. restore_migration_artifact
// 4. inspect_migration_target
// 5. rollback_migration_snapshot
// 6. cleanup_migration
func RegisterMigrationOperations(registry *Registry, migMgr *postgres.MigrationManager, logger *slog.Logger) {
	if registry == nil || migMgr == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	log := logger.With("component", "migration_operations")

	// 1. prepare_migration_target
	registry.Register("prepare_migration_target", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		var req postgres.PrepareTargetRequest
		if op.PayloadJson != "" {
			if err := json.Unmarshal([]byte(op.PayloadJson), &req); err != nil {
				return makeErrorResponse(op.OperationId, postgres.ErrCodeInvalidPayload, err), err
			}
		}
		if req.ResourceID == "" {
			req.ResourceID = op.ResourceId
		}
		if req.MigrationID == "" {
			req.MigrationID = op.OperationId
		}

		projectID := op.ProjectId
		if projectID == "" {
			projectID = "default"
		}

		resp, err := migMgr.PrepareTarget(ctx, projectID, &req)
		if err != nil {
			log.Error("prepare_migration_target_failed", "operation_id", op.OperationId, "error", err)
			return makeErrorResponse(op.OperationId, postgres.ErrCodeTargetNotReady, err), err
		}

		resBytes, _ := json.Marshal(resp)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Target container %s prepared and verified", resp.ContainerName),
			ResultJson:      string(resBytes),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, DefaultJSONValidator)

	// 2. create_migration_snapshot
	registry.Register("create_migration_snapshot", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		var req postgres.CreateSnapshotRequest
		if op.PayloadJson != "" {
			if err := json.Unmarshal([]byte(op.PayloadJson), &req); err != nil {
				return makeErrorResponse(op.OperationId, postgres.ErrCodeInvalidPayload, err), err
			}
		}
		if req.ResourceID == "" {
			req.ResourceID = op.ResourceId
		}
		if req.MigrationID == "" {
			req.MigrationID = op.OperationId
		}
		if req.SnapshotID == "" {
			req.SnapshotID = op.OperationId
		}

		projectID := op.ProjectId
		if projectID == "" {
			projectID = "default"
		}

		resp, err := migMgr.CreateSnapshot(ctx, projectID, &req)
		if err != nil {
			log.Error("create_migration_snapshot_failed", "operation_id", op.OperationId, "error", err)
			return makeErrorResponse(op.OperationId, postgres.ErrCodeSnapshotFailed, err), err
		}

		resBytes, _ := json.Marshal(resp)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Pre-migration snapshot %s created", resp.SnapshotID),
			ResultJson:      string(resBytes),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, DefaultJSONValidator)

	// 3. restore_migration_artifact
	registry.Register("restore_migration_artifact", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		var req postgres.RestoreArtifactRequest
		if op.PayloadJson != "" {
			if err := json.Unmarshal([]byte(op.PayloadJson), &req); err != nil {
				return makeErrorResponse(op.OperationId, postgres.ErrCodeInvalidPayload, err), err
			}
		}
		if req.ResourceID == "" {
			req.ResourceID = op.ResourceId
		}
		if req.MigrationID == "" {
			req.MigrationID = op.OperationId
		}

		projectID := op.ProjectId
		if projectID == "" {
			projectID = "default"
		}

		resp, err := migMgr.RestoreArtifact(ctx, projectID, &req)
		if err != nil {
			log.Error("restore_migration_artifact_failed", "operation_id", op.OperationId, "error", err)
			code := postgres.ErrCodeRestoreFailed
			if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), postgres.ErrCodeArtifactNotFound) {
				code = postgres.ErrCodeArtifactNotFound
			} else if strings.Contains(err.Error(), postgres.ErrCodeBinaryMissing) {
				code = postgres.ErrCodeBinaryMissing
			}
			return makeErrorResponse(op.OperationId, code, err), err
		}

		resBytes, _ := json.Marshal(resp)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Migration artifact restored using %s", resp.Command),
			ResultJson:      string(resBytes),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, DefaultJSONValidator)

	// 4. inspect_migration_target
	registry.Register("inspect_migration_target", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		var req postgres.InspectTargetRequest
		if op.PayloadJson != "" {
			if err := json.Unmarshal([]byte(op.PayloadJson), &req); err != nil {
				return makeErrorResponse(op.OperationId, postgres.ErrCodeInvalidPayload, err), err
			}
		}
		if req.ResourceID == "" {
			req.ResourceID = op.ResourceId
		}
		if req.MigrationID == "" {
			req.MigrationID = op.OperationId
		}

		projectID := op.ProjectId
		if projectID == "" {
			projectID = "default"
		}

		manifest, err := migMgr.InspectTarget(ctx, projectID, &req)
		if err != nil {
			log.Error("inspect_migration_target_failed", "operation_id", op.OperationId, "error", err)
			return makeErrorResponse(op.OperationId, postgres.ErrCodeInspectionFailed, err), err
		}

		resBytes, _ := json.Marshal(manifest)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Target database %s catalog inspected successfully", manifest.DatabaseName),
			ResultJson:      string(resBytes),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, DefaultJSONValidator)

	// 5. rollback_migration_snapshot
	registry.Register("rollback_migration_snapshot", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		var req postgres.RollbackSnapshotRequest
		if op.PayloadJson != "" {
			if err := json.Unmarshal([]byte(op.PayloadJson), &req); err != nil {
				return makeErrorResponse(op.OperationId, postgres.ErrCodeInvalidPayload, err), err
			}
		}
		if req.ResourceID == "" {
			req.ResourceID = op.ResourceId
		}
		if req.MigrationID == "" {
			req.MigrationID = op.OperationId
		}

		projectID := op.ProjectId
		if projectID == "" {
			projectID = "default"
		}

		resp, err := migMgr.RollbackSnapshot(ctx, projectID, &req)
		if err != nil {
			log.Error("rollback_migration_snapshot_failed", "operation_id", op.OperationId, "error", err)
			return makeErrorResponse(op.OperationId, postgres.ErrCodeRollbackFailed, err), err
		}

		resBytes, _ := json.Marshal(resp)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Pre-migration snapshot %s rolled back successfully", resp.RestoredSnapshotID),
			ResultJson:      string(resBytes),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, DefaultJSONValidator)

	// 6. cleanup_migration
	registry.Register("cleanup_migration", func(ctx context.Context, op *pb.OperationEnvelope) (*pb.OperationResponse, error) {
		var req postgres.CleanupMigrationRequest
		if op.PayloadJson != "" {
			if err := json.Unmarshal([]byte(op.PayloadJson), &req); err != nil {
				return makeErrorResponse(op.OperationId, postgres.ErrCodeInvalidPayload, err), err
			}
		}
		if req.ResourceID == "" {
			req.ResourceID = op.ResourceId
		}
		if req.MigrationID == "" {
			req.MigrationID = op.OperationId
		}

		resp, err := migMgr.CleanupMigration(ctx, &req)
		if err != nil {
			log.Error("cleanup_migration_failed", "operation_id", op.OperationId, "error", err)
			return makeErrorResponse(op.OperationId, postgres.ErrCodeCleanupFailed, err), err
		}

		resBytes, _ := json.Marshal(resp)
		return &pb.OperationResponse{
			OperationId:     op.OperationId,
			Status:          "SUCCEEDED",
			Message:         fmt.Sprintf("Cleaned ephemeral migration files (%d bytes freed)", resp.BytesFreed),
			ResultJson:      string(resBytes),
			CompletedAtUnix: time.Now().Unix(),
			ProgressPercent: 100,
		}, nil
	}, DefaultJSONValidator)
}

func makeErrorResponse(opID, errCode string, err error) *pb.OperationResponse {
	return &pb.OperationResponse{
		OperationId:     opID,
		Status:          "FAILED",
		ErrorCode:       errCode,
		Message:         err.Error(),
		CompletedAtUnix: time.Now().Unix(),
	}
}
