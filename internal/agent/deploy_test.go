package agent_test

import (
	"context"
	"strings"
	"testing"

	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

func TestAgent_RequiresProjectIdForSecretResolution(t *testing.T) {
	ag, _ := setupTestAgent(t)
	ctx := context.Background()
	dispatcher := ag.Dispatcher()

	if dispatcher == nil {
		t.Fatal("Dispatcher is nil")
	}

	// 1. Missing project_id when secrets are required
	payloadMissingProject := `{
		"application_id": "app-test-project-req",
		"image": "ghcr.io/primetech-nexus/apps/app-test-project-req:latest",
		"secret_refs": {
			"SECRET_KEY": "secret/data/primecloud/tenants/fake/applications/app-test-project-req/env#SECRET_KEY"
		}
	}`

	opMissingProject := &pb.OperationEnvelope{
		OperationId:   "op-test-missing-proj",
		OperationType: "deploy_application",
		ResourceId:    "app-test-project-req",
		ProjectId:     "", // Explicitly empty
		PayloadJson:   payloadMissingProject,
	}

	resp, err := dispatcher.Dispatch(ctx, opMissingProject)
	if err == nil && (resp == nil || resp.Status != "FAILED") {
		t.Fatal("expected deploy_application to fail when project_id is missing and secrets are requested")
	}

	if resp != nil {
		if resp.ErrorCode != "MISSING_PROJECT_ID" && resp.ErrorCode != "DEPLOYMENT_FAILED" {
			t.Errorf("expected MISSING_PROJECT_ID or DEPLOYMENT_FAILED error code, got: %s", resp.ErrorCode)
		}
		if !strings.Contains(resp.Message, "project_id is required") {
			t.Errorf("expected error message to mention 'project_id is required', got: %s", resp.Message)
		}
	}

	// 2. Missing project_id when vault: prefixed env var exists
	payloadWithVaultEnv := `{
		"application_id": "app-test-vault-prefix",
		"image": "ghcr.io/primetech-nexus/apps/app-test-vault-prefix:latest",
		"env": {
			"DATABASE_URL": "vault:secret/data/primecloud/tenants/fake/resources/postgres/pg-1#url"
		}
	}`

	opVaultEnv := &pb.OperationEnvelope{
		OperationId:   "op-test-vault-env",
		OperationType: "deploy_application",
		ResourceId:    "app-test-vault-prefix",
		ProjectId:     "", // Explicitly empty
		PayloadJson:   payloadWithVaultEnv,
	}

	resp, err = dispatcher.Dispatch(ctx, opVaultEnv)
	if err == nil && (resp == nil || resp.Status != "FAILED") {
		t.Fatal("expected deploy_application to fail when project_id is empty and vault: prefixed env exists")
	}
}
