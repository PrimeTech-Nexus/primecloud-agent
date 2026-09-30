package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/agent"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

func setupTestAgent(t *testing.T) (*agent.Agent, string) {
	tempDir := t.TempDir()
	cfg := agent.DefaultConfig()
	cfg.ResourceDir = tempDir
	cfg.VaultAddr = "" // No external vault in unit test

	ag, err := agent.NewAgent(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}
	return ag, tempDir
}

func TestAgent_ManagedPostgres_RegistrationAndDispatch(t *testing.T) {
	ag, tempDir := setupTestAgent(t)
	ctx := context.Background()
	dispatcher := ag.Dispatcher()

	if dispatcher == nil {
		t.Fatal("Dispatcher is nil")
	}

	resID := "pg-res-unit-1"
	volDir := filepath.Join(tempDir, "postgres", resID)

	// 1. Deprovision postgres (clean start)
	deprovOp := &pb.OperationEnvelope{
		OperationId:   "op-pg-deprov-0",
		OperationType: "deprovision_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `"}`,
	}
	resp, err := dispatcher.Dispatch(ctx, deprovOp)
	if err != nil {
		t.Logf("Initial deprovision had error: %v", err)
	} else if resp.Status != "SUCCEEDED" {
		t.Errorf("Expected deprovision SUCCEEDED, got %s", resp.Status)
	}

	// 2. Provision postgres
	provOp := &pb.OperationEnvelope{
		OperationId:   "op-pg-prov-1",
		OperationType: "provision_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `","version":"16"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, provOp)
	// If Docker daemon is not running locally, provision must fail truthfully
	if err != nil {
		if resp.Status != "FAILED" || resp.ErrorCode != "PROVISION_POSTGRES_FAILED" {
			t.Errorf("Expected truthful FAILED response, got %+v", resp)
		}
		t.Logf("Docker not running: truthfully failed as expected: %v", err)
	} else {
		if resp.Status != "SUCCEEDED" {
			t.Errorf("Expected SUCCEEDED, got %s", resp.Status)
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(resp.ResultJson), &data); err != nil {
			t.Errorf("Invalid ResultJson: %v", err)
		}
		if data["status"] != "AVAILABLE" {
			t.Errorf("Expected status AVAILABLE, got %v", data["status"])
		}
	}

	// 3. Stop postgres
	stopOp := &pb.OperationEnvelope{
		OperationId:   "op-pg-stop-1",
		OperationType: "stop_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, stopOp)
	if err != nil {
		if resp.Status != "FAILED" {
			t.Errorf("Expected FAILED status on error, got %s", resp.Status)
		}
	}

	// 4. Start postgres
	startOp := &pb.OperationEnvelope{
		OperationId:   "op-pg-start-1",
		OperationType: "start_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, startOp)
	if err != nil {
		if resp.Status != "FAILED" {
			t.Errorf("Expected FAILED status on error, got %s", resp.Status)
		}
	}

	// 5. Restart postgres
	restartOp := &pb.OperationEnvelope{
		OperationId:   "op-pg-restart-1",
		OperationType: "restart_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, restartOp)
	if err != nil {
		if resp.Status != "FAILED" {
			t.Errorf("Expected FAILED status on error, got %s", resp.Status)
		}
	}

	// 6. Health check postgres
	hcOp := &pb.OperationEnvelope{
		OperationId:   "op-pg-hc-1",
		OperationType: "health_check_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, hcOp)
	if err != nil {
		if resp.Status != "FAILED" {
			t.Errorf("Expected FAILED status on error, got %s", resp.Status)
		}
	}

	// 7. Deprovision postgres and verify volume cleanup
	_ = os.MkdirAll(volDir, 0700)
	deprovOp2 := &pb.OperationEnvelope{
		OperationId:   "op-pg-deprov-2",
		OperationType: "deprovision_postgres",
		ResourceId:    resID,
		PayloadJson:   `{"postgres_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, deprovOp2)
	if err != nil {
		if resp.Status != "FAILED" || resp.ErrorCode != "DEPROVISION_POSTGRES_FAILED" {
			t.Errorf("Expected truthful FAILED response, got %+v", resp)
		}
		t.Logf("Docker not running: deprovision truthfully failed: %v", err)
	} else {
		if resp.Status != "SUCCEEDED" {
			t.Errorf("Expected SUCCEEDED, got %s", resp.Status)
		}
		if _, statErr := os.Stat(volDir); !os.IsNotExist(statErr) {
			t.Errorf("Expected volume directory %s to be deleted after deprovision", volDir)
		}
	}
}

func TestAgent_ManagedValkey_RegistrationAndDispatch(t *testing.T) {
	ag, tempDir := setupTestAgent(t)
	ctx := context.Background()
	dispatcher := ag.Dispatcher()

	resID := "vk-res-unit-1"
	volDir := filepath.Join(tempDir, "valkey", resID)

	// 1. Provision keyvalue (alias provision_valkey)
	provOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-prov-1",
		OperationType: "provision_keyvalue",
		ResourceId:    resID,
		PayloadJson:   `{"keyvalue_id":"` + resID + `","version":"7.2"}`,
	}
	resp, err := dispatcher.Dispatch(ctx, provOp)
	if err != nil {
		if resp.Status != "FAILED" || resp.ErrorCode != "PROVISION_VALKEY_FAILED" {
			t.Errorf("Expected truthful FAILED response, got %+v", resp)
		}
		t.Logf("Docker not running: truthfully failed as expected: %v", err)
	} else {
		if resp.Status != "SUCCEEDED" {
			t.Errorf("Expected SUCCEEDED, got %s", resp.Status)
		}
	}

	// 2. Test aliases
	aliasProvOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-prov-2",
		OperationType: "provision_valkey",
		ResourceId:    "vk-res-unit-2",
		PayloadJson:   `{"keyvalue_id":"vk-res-unit-2"}`,
	}
	respAlias, errAlias := dispatcher.Dispatch(ctx, aliasProvOp)
	if errAlias != nil {
		if respAlias.Status != "FAILED" || respAlias.ErrorCode != "PROVISION_VALKEY_FAILED" {
			t.Errorf("Expected truthful FAILED response, got %+v", respAlias)
		}
	}

	// 3. Stop keyvalue
	stopOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-stop-1",
		OperationType: "stop_keyvalue",
		ResourceId:    resID,
		PayloadJson:   `{"keyvalue_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, stopOp)
	if err != nil && resp.Status != "FAILED" {
		t.Errorf("Expected FAILED status on error, got %s", resp.Status)
	}

	// 4. Start keyvalue
	startOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-start-1",
		OperationType: "start_keyvalue",
		ResourceId:    resID,
		PayloadJson:   `{"keyvalue_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, startOp)
	if err != nil && resp.Status != "FAILED" {
		t.Errorf("Expected FAILED status on error, got %s", resp.Status)
	}

	// 5. Restart keyvalue
	restartOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-restart-1",
		OperationType: "restart_keyvalue",
		ResourceId:    resID,
		PayloadJson:   `{"keyvalue_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, restartOp)
	if err != nil && resp.Status != "FAILED" {
		t.Errorf("Expected FAILED status on error, got %s", resp.Status)
	}

	// 6. Health check keyvalue
	hcOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-hc-1",
		OperationType: "health_check_keyvalue",
		ResourceId:    resID,
		PayloadJson:   `{"keyvalue_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, hcOp)
	if err != nil && resp.Status != "FAILED" {
		t.Errorf("Expected FAILED status on error, got %s", resp.Status)
	}

	// 7. Deprovision keyvalue and verify volume cleanup
	_ = os.MkdirAll(volDir, 0700)
	deprovOp := &pb.OperationEnvelope{
		OperationId:   "op-vk-deprov-1",
		OperationType: "deprovision_keyvalue",
		ResourceId:    resID,
		PayloadJson:   `{"keyvalue_id":"` + resID + `"}`,
	}
	resp, err = dispatcher.Dispatch(ctx, deprovOp)
	if err != nil {
		if resp.Status != "FAILED" || resp.ErrorCode != "DEPROVISION_VALKEY_FAILED" {
			t.Errorf("Expected truthful FAILED response, got %+v", resp)
		}
		t.Logf("Docker not running: deprovision truthfully failed: %v", err)
	} else {
		if resp.Status != "SUCCEEDED" {
			t.Errorf("Expected SUCCEEDED, got %s", resp.Status)
		}
		if _, statErr := os.Stat(volDir); !os.IsNotExist(statErr) {
			t.Errorf("Expected volume directory %s to be deleted after deprovision", volDir)
		}
	}
}
