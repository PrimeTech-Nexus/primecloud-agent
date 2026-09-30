package applications_test

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/runtime"
)

type mockRuntime struct {
	pullImageCalled       bool
	pullImageRef          string
	pullAuthBase64        string
	pullErr               error
	createContainerCalled bool
	createImage           string
	containerID           string
	createErr             error
	startContainerCalled  bool
}

func (m *mockRuntime) PullImage(ctx context.Context, imageRef string) error {
	m.pullImageCalled = true
	m.pullImageRef = imageRef
	return m.pullErr
}

func (m *mockRuntime) PullImageWithAuth(ctx context.Context, imageRef string, authBase64 string) error {
	m.pullImageCalled = true
	m.pullImageRef = imageRef
	m.pullAuthBase64 = authBase64
	return m.pullErr
}

func (m *mockRuntime) CreateContainer(ctx context.Context, cfg *runtime.ContainerConfig, limits *runtime.ResourceLimits, profile *runtime.HardenedIsolationProfile) (string, error) {
	m.createContainerCalled = true
	if cfg != nil {
		m.createImage = cfg.Image
	}
	if m.createErr != nil {
		return "", m.createErr
	}
	return m.containerID, nil
}

func (m *mockRuntime) StartContainer(ctx context.Context, containerID string) error {
	m.startContainerCalled = true
	return nil
}

func (m *mockRuntime) StopContainer(ctx context.Context, containerID string, timeoutSec *int) error {
	return nil
}

func (m *mockRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	return nil
}

func (m *mockRuntime) InspectContainer(ctx context.Context, containerID string) (*runtime.ContainerInspect, error) {
	return &runtime.ContainerInspect{
		ID:      containerID,
		Running: true,
		Health:  "healthy",
	}, nil
}

func (m *mockRuntime) ListContainers(ctx context.Context, all bool) ([]runtime.ContainerSummary, error) {
	return nil, nil
}

func (m *mockRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockRuntime) Ping(ctx context.Context) error {
	return nil
}

func (m *mockRuntime) Close() error {
	return nil
}

func TestDeploy_PullsImageBeforeCreate(t *testing.T) {
	mockRT := &mockRuntime{
		containerID: "cnt-test-12345",
	}

	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"image_digest": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"ports": {"8080": "8080"}
	}`

	cid, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed unexpectedly: %v", err)
	}

	if !mockRT.pullImageCalled {
		t.Fatal("Expected PullImageWithAuth to be called before container creation")
	}

	if mockRT.pullImageRef != "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90" {
		t.Fatalf("Expected pull image ref 'ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90', got %q", mockRT.pullImageRef)
	}

	if !mockRT.createContainerCalled {
		t.Fatal("Expected CreateContainer to be called after image pull")
	}

	if mockRT.createImage != "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90" {
		t.Fatalf("Expected container image 'ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90', got %q", mockRT.createImage)
	}

	if cid != "cnt-test-12345" {
		t.Fatalf("Expected container ID 'cnt-test-12345', got %q", cid)
	}
}

func TestDeploy_PullFailureAbortsBeforeCreate(t *testing.T) {
	mockRT := &mockRuntime{
		pullErr: errors.New("unauthorized: authentication required"),
	}

	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"ports": {"8080": "8080"}
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err == nil {
		t.Fatal("Expected Deploy to return error when PullImage fails")
	}

	if !mockRT.pullImageCalled {
		t.Fatal("Expected PullImageWithAuth to be attempted")
	}

	if mockRT.createContainerCalled {
		t.Fatal("CreateContainer must NEVER be called if PullImage fails")
	}
}

func TestDeploy_PassesGHCRAuthToPull(t *testing.T) {
	origUser := os.Getenv("GHCR_USERNAME")
	origTok := os.Getenv("GHCR_TOKEN")
	defer func() {
		os.Setenv("GHCR_USERNAME", origUser)
		os.Setenv("GHCR_TOKEN", origTok)
	}()

	os.Setenv("GHCR_USERNAME", "deployer-user")
	os.Setenv("GHCR_TOKEN", "ghp_mock_token_12345")

	mockRT := &mockRuntime{
		containerID: "cnt-auth-success-123",
	}

	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"ports": {"8080": "8080"}
	}`

	cid, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("unexpected deploy failure: %v", err)
	}

	if cid != "cnt-auth-success-123" {
		t.Errorf("expected container id cnt-auth-success-123, got %s", cid)
	}

	if !mockRT.pullImageCalled {
		t.Fatal("expected PullImageWithAuth to be called")
	}

	expectedAuth := runtime.EncodeGHCRAuth("deployer-user", "ghp_mock_token_12345")
	if mockRT.pullAuthBase64 != expectedAuth {
		t.Fatalf("expected pull auth %s, got %s", expectedAuth, mockRT.pullAuthBase64)
	}
}

func TestDeploy_RejectsBareSha256(t *testing.T) {
	mockRT := &mockRuntime{}
	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err == nil {
		t.Fatal("Expected Deploy to reject bare sha256 image reference")
	}

	if mockRT.pullImageCalled || mockRT.createContainerCalled {
		t.Fatal("Neither PullImage nor CreateContainer should be invoked for bare sha256")
	}
}


