package agent_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/agent"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

type failingRuntime struct {
	runtime.ContainerRuntime
}

func (f *failingRuntime) Ping(ctx context.Context) error {
	return fmt.Errorf("connection refused: docker daemon is dead")
}

func TestNodeFailure_HealthAssessmentAndDegradation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Initial State: healthy (nil submodules in unit mode)
	handler := agent.NewFailureHandler(nil, nil, nil)
	report := handler.AssessHealth(ctx)
	if report.Status != agent.StatusHealthy {
		t.Errorf("Expected StatusHealthy, got %v", report.Status)
	}

	canAccept, reason := handler.CanAcceptOperations()
	if !canAccept {
		t.Errorf("Expected CanAcceptOperations=true, got false: %s", reason)
	}

	// 2. Test Drain Mode
	handler.SetDrain(true)
	report = handler.AssessHealth(ctx)
	if report.Status != agent.StatusDegraded {
		t.Errorf("Expected StatusDegraded when draining, got %v", report.Status)
	}

	canAccept, reason = handler.CanAcceptOperations()
	if canAccept {
		t.Error("Expected CanAcceptOperations=false when draining")
	}
	if reason != "node is in drain mode" {
		t.Errorf("Unexpected rejection reason: %s", reason)
	}

	handler.SetDrain(false)

	// 3. Test Vault Failure (unreachable URL)
	badVaultClient, _ := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:54321",
		Token:   "bad-token",
		Timeout: 500 * time.Millisecond,
	})
	vaultHandler := agent.NewFailureHandler(nil, badVaultClient, nil)
	report = vaultHandler.AssessHealth(ctx)
	if report.Status != agent.StatusDegraded {
		t.Errorf("Expected StatusDegraded for unreachable Vault, got %v", report.Status)
	}

	// 4. Test Docker Runtime Failure -> UNHEALTHY
	failHandler := agent.NewFailureHandler(&failingRuntime{}, nil, nil)
	report = failHandler.AssessHealth(ctx)
	if report.Status != agent.StatusUnhealthy {
		t.Errorf("Expected StatusUnhealthy when docker is down, got %v", report.Status)
	}

	canAccept, _ = failHandler.CanAcceptOperations()
	if canAccept {
		t.Error("Expected CanAcceptOperations=false when unhealthy")
	}
}
