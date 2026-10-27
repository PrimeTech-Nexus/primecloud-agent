package recovery_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/mongodb"
	"github.com/primecloud/primecloud-agent/internal/mysql"
	"github.com/primecloud/primecloud-agent/internal/postgres"
	"github.com/primecloud/primecloud-agent/internal/recovery"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/valkey"
)

// =============================================================================
// 1. Adversarial In-Place Overwrite Confirmation Tests
// =============================================================================

func TestAdversarial_InPlaceOverwrite_Rejections(t *testing.T) {
	adversarialInputs := []struct {
		name             string
		mode             string
		confirmOverwrite bool
		resourceID       string
		targetContainer  string
		expectedErrCode  string
	}{
		{
			name:             "ExplicitFalseConfirm",
			mode:             "IN_PLACE_OVERWRITE",
			confirmOverwrite: false,
			resourceID:       "pg-victim-001",
			expectedErrCode:  "OVERWRITE_CONFIRMATION_REQUIRED",
		},
		{
			name:             "CaseInsensitive_in_place_overwrite",
			mode:             "in_place_overwrite",
			confirmOverwrite: false,
			resourceID:       "pg-victim-002",
			expectedErrCode:  "OVERWRITE_CONFIRMATION_REQUIRED",
		},
		{
			name:             "Padded_IN_PLACE_OVERWRITE",
			mode:             "  IN_PLACE_OVERWRITE  ",
			confirmOverwrite: false,
			resourceID:       "pg-victim-003",
			expectedErrCode:  "OVERWRITE_CONFIRMATION_REQUIRED",
		},
		{
			name:             "InvalidTargetMode_DROP",
			mode:             "DROP_DATABASE",
			confirmOverwrite: true,
			resourceID:       "pg-victim-004",
			expectedErrCode:  "TARGET_MODE_INVALID",
		},
		{
			name:             "InvalidTargetMode_RAW_EXEC",
			mode:             "EXEC_SHELL",
			confirmOverwrite: true,
			resourceID:       "pg-victim-005",
			expectedErrCode:  "TARGET_MODE_INVALID",
		},
	}

	for _, tc := range adversarialInputs {
		t.Run(tc.name, func(t *testing.T) {
			err := recovery.ValidateRestoreSafety(recovery.RestoreSafetyConfig{
				TargetMode:       tc.mode,
				TargetContainer:  tc.targetContainer,
				ConfirmOverwrite: tc.confirmOverwrite,
				ResourceID:       tc.resourceID,
			})
			if err == nil {
				t.Fatalf("expected error containing %s, but got nil", tc.expectedErrCode)
			}
			if !strings.Contains(err.Error(), tc.expectedErrCode) {
				t.Fatalf("expected error containing %s, got: %v", tc.expectedErrCode, err)
			}
		})
	}
}

// =============================================================================
// 2. Adversarial Source Container Substitution Attempts (NEW_INSTANCE)
// =============================================================================

func TestAdversarial_SourceContainerSubstitution_Rejections(t *testing.T) {
	resID := "res-db-victim-999"
	sourceContainerTricks := []struct {
		name            string
		targetContainer string
		expectedErrCode string
	}{
		{
			name:            "EmptyTarget",
			targetContainer: "",
			expectedErrCode: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name:            "SpacesOnlyTarget",
			targetContainer: "     ",
			expectedErrCode: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name:            "TabsOnlyTarget",
			targetContainer: "\t\t\t",
			expectedErrCode: "TARGET_CONTAINER_REQUIRED",
		},
		{
			name:            "ExactResourceID",
			targetContainer: resID,
			expectedErrCode: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "ExactPostgresSourceContainer",
			targetContainer: fmt.Sprintf("pc-pg-%s", resID),
			expectedErrCode: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "ExactMySQLSourceContainer",
			targetContainer: fmt.Sprintf("pc-my-%s", resID),
			expectedErrCode: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "ExactMongoSourceContainer",
			targetContainer: fmt.Sprintf("pc-mg-%s", resID),
			expectedErrCode: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "ExactValkeySourceContainer",
			targetContainer: fmt.Sprintf("pc-vk-%s", resID),
			expectedErrCode: "TARGET_CONTAINER_INVALID",
		},
		{
			name:            "PaddedPostgresSourceContainer",
			targetContainer: fmt.Sprintf("  pc-pg-%s  ", resID),
			expectedErrCode: "TARGET_CONTAINER_INVALID",
		},
	}

	for _, tc := range sourceContainerTricks {
		t.Run(tc.name, func(t *testing.T) {
			err := recovery.ValidateRestoreSafety(recovery.RestoreSafetyConfig{
				TargetMode:       "NEW_INSTANCE",
				TargetContainer:  tc.targetContainer,
				ConfirmOverwrite: false,
				ResourceID:       resID,
			})
			if err == nil {
				t.Fatalf("expected error containing %s, but got nil", tc.expectedErrCode)
			}
			if !strings.Contains(err.Error(), tc.expectedErrCode) {
				t.Fatalf("expected error containing %s, got: %v", tc.expectedErrCode, err)
			}
		})
	}
}

// =============================================================================
// 3. Credential Exposure Audit across Database Drivers (AC-1.15)
// =============================================================================

func TestAdversarial_DatabaseDrivers_CredentialSafety(t *testing.T) {
	ctx := context.Background()
	rt := newMockSafetyRuntime()
	tmpDir := t.TempDir()

	// --- 3.1 PostgreSQL Driver ---
	t.Run("PostgreSQL_NoCredentialsInArgs", func(t *testing.T) {
		pgDump := filepath.Join(tmpDir, "pg.dump")
		_ = os.WriteFile(pgDump, []byte("PGDMP\x01\x02\x03dummy"), 0600)
		pgSandbox := "pc_drill_tgt_pg_leak_test"

		err := postgres.RestorePostgresWithVault(ctx, rt, nil, "default", "pg-res-1", pgDump, pgSandbox)
		if err != nil {
			t.Fatalf("Postgres restore failed: %v", err)
		}

		for _, call := range rt.execCalls {
			if call.ContainerID != pgSandbox {
				continue
			}
			// Inspect command line arguments
			for _, arg := range call.Cmd {
				if strings.Contains(strings.ToLower(arg), "password") {
					t.Errorf("Potential credential leak in Postgres cmd argument: %s", arg)
				}
			}
			// Verify password is passed in environment (PGPASSWORD)
			var hasPgPassword bool
			for _, envVar := range call.Env {
				if strings.HasPrefix(envVar, "PGPASSWORD=") {
					hasPgPassword = true
					break
				}
			}
			cmdStr := strings.Join(call.Cmd, " ")
			if (strings.Contains(cmdStr, "pg_restore") || strings.Contains(cmdStr, "psql")) && !hasPgPassword {
				t.Errorf("Expected PGPASSWORD in env for %s", cmdStr)
			}
		}
	})

	// --- 3.2 MongoDB Driver ---
	t.Run("MongoDB_NoCredentialsInArgs", func(t *testing.T) {
		mgArchive := filepath.Join(tmpDir, "mg.archive")
		_ = os.WriteFile(mgArchive, []byte("dummy mongo data"), 0600)
		mgTarget := "pc_drill_tgt_mg_leak_test"

		rt.containers[mgTarget] = &runtime.ContainerInspect{
			ID:      mgTarget,
			Name:    mgTarget,
			Running: true,
			State:   "running",
		}

		err := mongodb.RestoreMongoDBWithVault(ctx, rt, nil, "default", "mg-res-1", mgArchive, mgTarget)
		if err != nil {
			t.Fatalf("Mongo restore failed: %v", err)
		}

		for _, call := range rt.execCalls {
			if call.ContainerID != mgTarget {
				continue
			}
			cmdStr := strings.Join(call.Cmd, " ")
			// Ensure password was not substituted as literal string into call.Cmd
			// Default password in mock is "password"
			if strings.Contains(cmdStr, "--password password") || strings.Contains(cmdStr, "-p password") {
				t.Fatalf("SECURITY VIOLATION: MongoDB command-line args leak plaintext password: %s", cmdStr)
			}
			// Ensure it uses shell variable indirection
			if strings.Contains(cmdStr, "mongorestore") && !strings.Contains(cmdStr, "\"$MONGO_PASS\"") {
				t.Fatalf("Expected mongorestore to reference $MONGO_PASS, got: %s", cmdStr)
			}
		}
	})

	// --- 3.3 MySQL Driver ---
	t.Run("MySQL_NoCredentialsInArgs", func(t *testing.T) {
		mySql := filepath.Join(tmpDir, "my.sql")
		_ = os.WriteFile(mySql, []byte("SELECT 1;"), 0600)
		myTarget := "pc_drill_tgt_my_leak_test"

		rt.containers[myTarget] = &runtime.ContainerInspect{
			ID:      myTarget,
			Name:    myTarget,
			Running: true,
			State:   "running",
		}

		err := mysql.RestoreMySQLWithVault(ctx, rt, nil, "default", "my-res-1", mySql, myTarget)
		if err != nil {
			t.Fatalf("MySQL restore failed: %v", err)
		}

		for _, call := range rt.execCalls {
			if call.ContainerID != myTarget {
				continue
			}
			cmdStr := strings.Join(call.Cmd, " ")
			if strings.Contains(cmdStr, "-p") || strings.Contains(cmdStr, "--password") {
				t.Fatalf("SECURITY VIOLATION: MySQL command-line args leak password flag: %s", cmdStr)
			}
			// Check MYSQL_PWD in env
			var hasMyPwd bool
			for _, envVar := range call.Env {
				if strings.HasPrefix(envVar, "MYSQL_PWD=") {
					hasMyPwd = true
					break
				}
			}
			if !hasMyPwd {
				t.Errorf("Expected MYSQL_PWD in env for MySQL call: %s", cmdStr)
			}
		}
	})

	// --- 3.4 Valkey Driver Inspection ---
	t.Run("Valkey_InspectPingArgs", func(t *testing.T) {
		vkRdb := filepath.Join(tmpDir, "dump.rdb")
		_ = os.WriteFile(vkRdb, []byte("REDIS0011dummydata"), 0600)
		vkTarget := "pc_drill_tgt_vk_leak_test"

		rt.containers[vkTarget] = &runtime.ContainerInspect{
			ID:      vkTarget,
			Name:    vkTarget,
			Running: true,
			State:   "running",
		}

		err := valkey.RestoreValkeyWithVault(ctx, rt, nil, tmpDir, "default", "vk-res-1", vkRdb, vkTarget)
		if err != nil {
			t.Fatalf("Valkey restore failed: %v", err)
		}

		for _, call := range rt.execCalls {
			if call.ContainerID != vkTarget {
				continue
			}
			// Inspect Valkey ping commands
			cmdStr := strings.Join(call.Cmd, " ")
			t.Logf("Valkey exec call observed: %s", cmdStr)
		}
	})
}
