package applications_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

type mockRuntime struct {
	pullImageCalled       bool
	pullImageRef          string
	pullAuthBase64        string
	pullErr               error
	createContainerCalled bool
	createImage           string
	createdConfig         *runtime.ContainerConfig
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
	m.createdConfig = cfg
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

func TestDeploy_PayloadDeserializationAndVaultResolution_KVv2(t *testing.T) {
	// Mock HashiCorp Vault server returning KV v2 nested secret data
	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "secret/data/primecloud/tenants/proj-1/applications/app-1/env") {
			// KV v2 envelope structure: {"data": {"data": { ... }}}
			fmt.Fprintln(w, `{
				"data": {
					"data": {
						"SECRET_KEY": "super-secret-vault-val",
						"DATABASE_URL": "postgresql://postgres:secretpw@db:5432/production"
					},
					"metadata": {
						"version": 1
					}
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer vaultSrv.Close()

	vClient, err := vault.NewClient(vault.Config{
		Address: vaultSrv.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create test vault client: %v", err)
	}

	mockRT := &mockRuntime{
		containerID: "cnt-full-env-success",
	}

	deployer := applications.NewDeployer(mockRT, vClient, nil)
	ctx := context.Background()

	// Payload with normal env, secret_refs, and env_vars (unified control plane schema)
	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"ports": {"8000": "8000"},
		"env": {
			"PORT": "8000"
		},
		"secret_refs": {
			"SECRET_KEY": "secret/data/primecloud/tenants/proj-1/applications/app-1/env#SECRET_KEY"
		},
		"env_vars": {
			"NODE_ENV": "production",
			"DATABASE_URL": "vault:secret/data/primecloud/tenants/proj-1/applications/app-1/env#DATABASE_URL"
		}
	}`

	cid, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed: %v", err)
	}

	if cid != "cnt-full-env-success" {
		t.Fatalf("expected container id cnt-full-env-success, got %s", cid)
	}

	if !mockRT.createContainerCalled {
		t.Fatal("expected CreateContainer to be called")
	}

	if mockRT.createdConfig == nil {
		t.Fatal("expected createdConfig to be set")
	}

	envMap := mockRT.createdConfig.Env
	if len(envMap) != 4 {
		t.Fatalf("expected 4 environment variables in container config, got %d: %v", len(envMap), envMap)
	}

	if envMap["PORT"] != "8000" {
		t.Errorf("expected PORT=8000, got %q", envMap["PORT"])
	}
	if envMap["NODE_ENV"] != "production" {
		t.Errorf("expected NODE_ENV=production, got %q", envMap["NODE_ENV"])
	}
	if envMap["SECRET_KEY"] != "super-secret-vault-val" {
		t.Errorf("expected SECRET_KEY=super-secret-vault-val, got %q", envMap["SECRET_KEY"])
	}
	if envMap["DATABASE_URL"] != "postgresql://postgres:secretpw@db:5432/production" {
		t.Errorf("expected DATABASE_URL to match Vault secret value, got %q", envMap["DATABASE_URL"])
	}
}

func TestDeploy_SecretResolution_PathWithoutKey(t *testing.T) {
	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"data": {
				"data": {
					"CUSTOM_SECRET": "resolved-by-var-name"
				}
			}
		}`)
	}))
	defer vaultSrv.Close()

	vClient, err := vault.NewClient(vault.Config{
		Address: vaultSrv.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create test vault client: %v", err)
	}

	mockRT := &mockRuntime{
		containerID: "cnt-path-without-key",
	}

	deployer := applications.NewDeployer(mockRT, vClient, nil)
	ctx := context.Background()

	// Path without "#key"
	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"secret_refs": {
			"CUSTOM_SECRET": "secret/data/primecloud/tenants/proj-1/applications/app-1/env"
		}
	}`

	_, err = deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed: %v", err)
	}

	if mockRT.createdConfig.Env["CUSTOM_SECRET"] != "resolved-by-var-name" {
		t.Errorf("expected CUSTOM_SECRET=resolved-by-var-name, got %q", mockRT.createdConfig.Env["CUSTOM_SECRET"])
	}
}

func TestDeploy_FailClosed_WhenSecretsRequiredAndVaultClientNil(t *testing.T) {
	mockRT := &mockRuntime{}
	// Deployer initialized with nil vault client
	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"secret_refs": {
			"SECRET_KEY": "secret/data/primecloud/tenants/proj-1/applications/app-1/env#SECRET_KEY"
		}
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err == nil {
		t.Fatal("expected Deploy to FAIL CLOSED when secret_refs are present but vaultClient is nil")
	}

	if !strings.Contains(err.Error(), "vault client is not configured") {
		t.Errorf("expected fail-closed error message about vault client, got: %v", err)
	}

	if mockRT.createContainerCalled {
		t.Fatal("CreateContainer MUST NOT be called when secret resolution fails closed")
	}
}

func TestDeploy_ZeroSecretsPassThroughWithoutVault(t *testing.T) {
	mockRT := &mockRuntime{
		containerID: "cnt-no-secrets",
	}
	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"env": {
			"PORT": "8080",
			"DEBUG": "true"
		},
		"env_vars": {
			"NODE_ENV": "development"
		}
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed for zero-secrets app: %v", err)
	}

	if !mockRT.createContainerCalled {
		t.Fatal("expected CreateContainer to be called")
	}

	envMap := mockRT.createdConfig.Env
	if len(envMap) != 3 {
		t.Fatalf("expected 3 environment variables, got %d: %v", len(envMap), envMap)
	}

	if envMap["PORT"] != "8080" || envMap["DEBUG"] != "true" || envMap["NODE_ENV"] != "development" {
		t.Errorf("expected normal env vars preserved, got %v", envMap)
	}
}

func TestDeploy_CanonicalImageWithOciDigestProvenance(t *testing.T) {
	mockRT := &mockRuntime{
		containerID: "cnt-canonical-image",
	}
	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	// Canonical payload required by Go Agent
	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"image_reference": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"image_digest": "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed for canonical image payload: %v", err)
	}

	if !mockRT.pullImageCalled {
		t.Fatal("expected PullImageWithAuth to be called")
	}
	if mockRT.pullImageRef != "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90" {
		t.Fatalf("expected pulled image to be ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90, got: %s", mockRT.pullImageRef)
	}
	if mockRT.createImage != "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90" {
		t.Fatalf("expected created container image to be ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90, got: %s", mockRT.createImage)
	}
}

func TestDeploy_FallbackToImageReferenceWhenImageIsBareDigestOrEmpty(t *testing.T) {
	mockRT := &mockRuntime{
		containerID: "cnt-fallback-ref",
	}
	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	// Image is bare digest, image_reference has canonical registry reference
	payloadJSON := `{
		"image": "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e",
		"image_reference": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"image_digest": "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed with image_reference fallback: %v", err)
	}

	if mockRT.pullImageRef != "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90" {
		t.Fatalf("expected fallback to image_reference, got: %s", mockRT.pullImageRef)
	}
}

func TestDeploy_RejectsBareSha256DigestWithoutCanonicalReference(t *testing.T) {
	mockRT := &mockRuntime{
		containerID: "cnt-bare-digest",
	}
	deployer := applications.NewDeployer(mockRT, nil, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e",
		"image_digest": "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
	}`

	_, err := deployer.Deploy(ctx, "proj-1", "env-1", "app-1", "inst-1", payloadJSON)
	if err == nil {
		t.Fatal("expected Deploy to fail when only bare sha256 digest is provided")
	}

	expectedErr := "invalid image reference: bare sha256 digest is not pullable; canonical registry reference required"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error containing %q, got %q", expectedErr, err.Error())
	}
}

func TestDeploy_AppRoleAuthenticated_SecretResolution(t *testing.T) {
	var vaultLoginCalled bool
	var secretReadCalled bool

	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			vaultLoginCalled = true
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] != "agent-role-uuid" || body["secret_id"] != "agent-secret-uuid" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, `{"errors":["invalid approle credentials"]}`)
				return
			}
			fmt.Fprintln(w, `{
				"auth": {
					"client_token": "s.agent-authenticated-token",
					"lease_duration": 3600,
					"policies": ["agent-policy"]
				}
			}`)
		case "/v1/secret/data/primecloud/tenants/proj-prod/applications/platelikbackend/env":
			secretReadCalled = true
			token := r.Header.Get("X-Vault-Token")
			if token != "s.agent-authenticated-token" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, `{"errors":["permission denied"]}`)
				return
			}
			fmt.Fprintln(w, `{
				"data": {
					"data": {
						"DATABASE_URL": "postgresql://prod_user:p4ssw0rd@db.internal:5432/proddb",
						"PAYSTACK_SECRET": "sk_live_verysecretstring987"
					}
				}
			}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer vaultSrv.Close()

	vClient, err := vault.NewClient(vault.Config{
		Address:  vaultSrv.URL,
		RoleID:   "agent-role-uuid",
		SecretID: "agent-secret-uuid",
	})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}

	mockRT := &mockRuntime{
		containerID: "cnt-approle-deploy-success",
	}

	deployer := applications.NewDeployer(mockRT, vClient, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/platelikbackend:013c8c90",
		"env": {
			"PORT": "8080",
			"NODE_ENV": "production"
		},
		"secret_refs": {
			"DATABASE_URL": "secret/data/primecloud/tenants/proj-prod/applications/platelikbackend/env#DATABASE_URL",
			"PAYSTACK_SECRET": "secret/data/primecloud/tenants/proj-prod/applications/platelikbackend/env#PAYSTACK_SECRET"
		}
	}`

	cid, err := deployer.Deploy(ctx, "proj-prod", "env-prod", "platelikbackend", "inst-1", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy failed: %v", err)
	}

	if cid != "cnt-approle-deploy-success" {
		t.Fatalf("expected container ID cnt-approle-deploy-success, got %s", cid)
	}

	if !vaultLoginCalled {
		t.Fatal("expected AppRole login to be executed")
	}
	if !secretReadCalled {
		t.Fatal("expected secret read to be executed")
	}

	if !mockRT.createContainerCalled || mockRT.createdConfig == nil {
		t.Fatal("expected CreateContainer to be called with valid container config")
	}

	envMap := mockRT.createdConfig.Env
	if envMap["PORT"] != "8080" {
		t.Errorf("expected PORT=8080, got %q", envMap["PORT"])
	}
	if envMap["NODE_ENV"] != "production" {
		t.Errorf("expected NODE_ENV=production, got %q", envMap["NODE_ENV"])
	}
	if envMap["DATABASE_URL"] != "postgresql://prod_user:p4ssw0rd@db.internal:5432/proddb" {
		t.Errorf("expected DATABASE_URL to be resolved, got %q", envMap["DATABASE_URL"])
	}
	if envMap["PAYSTACK_SECRET"] != "sk_live_verysecretstring987" {
		t.Errorf("expected PAYSTACK_SECRET to be resolved, got %q", envMap["PAYSTACK_SECRET"])
	}
}

func TestDeploy_SecretResolution_CrossMountFallback_PreservesDataEndpoint(t *testing.T) {
	// Mock Vault server where secret/ returns 404/403, but primecloud/data/primecloud/... contains the secret
	var pathsRequested []string
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathsRequested = append(pathsRequested, r.URL.Path)

		if strings.HasPrefix(r.URL.Path, "/v1/secret/data/") {
			// secret/ mount does not have it (simulating missing mount or migration state)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["not found"]}`))
			return
		}

		if strings.HasPrefix(r.URL.Path, "/v1/primecloud/data/primecloud/tenants/proj-cross/applications/app-cross/env") {
			// Successfully served under primecloud KV v2 mount
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"data": {
					"data": {
						"ARBITRARY_API_KEY": "arbitrary_val_12345",
						"CUSTOM_VAR": "custom_val_67890"
					}
				}
			}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer vaultServer.Close()

	vClient, err := vault.NewClient(vault.Config{
		Address: vaultServer.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}

	mockRT := &mockRuntime{
		containerID: "cnt-cross-mount-success",
	}

	deployer := applications.NewDeployer(mockRT, vClient, nil)
	ctx := context.Background()

	payloadJSON := `{
		"image": "ghcr.io/primetech-nexus/apps/app-cross:latest",
		"secret_refs": {
			"ARBITRARY_API_KEY": "secret/data/primecloud/tenants/proj-cross/applications/app-cross/env#ARBITRARY_API_KEY",
			"CUSTOM_VAR": "secret/data/primecloud/tenants/proj-cross/applications/app-cross/env#CUSTOM_VAR"
		}
	}`

	cid, err := deployer.Deploy(ctx, "proj-cross", "env-cross", "app-cross", "inst-cross", payloadJSON)
	if err != nil {
		t.Fatalf("Deploy with cross-mount fallback failed: %v", err)
	}

	if cid != "cnt-cross-mount-success" {
		t.Fatalf("expected container ID cnt-cross-mount-success, got %s", cid)
	}

	if mockRT.createdConfig == nil {
		t.Fatal("expected container config to be populated")
	}

	envMap := mockRT.createdConfig.Env
	if envMap["ARBITRARY_API_KEY"] != "arbitrary_val_12345" {
		t.Errorf("expected ARBITRARY_API_KEY=arbitrary_val_12345, got %q", envMap["ARBITRARY_API_KEY"])
	}
	if envMap["CUSTOM_VAR"] != "custom_val_67890" {
		t.Errorf("expected CUSTOM_VAR=custom_val_67890, got %q", envMap["CUSTOM_VAR"])
	}

	// Verify that the requested tenant environment paths never stripped /data/ to bare primecloud/...
	for _, p := range pathsRequested {
		if strings.Contains(p, "tenants") && strings.HasPrefix(p, "/v1/primecloud/") && !strings.HasPrefix(p, "/v1/primecloud/data/") {
			t.Errorf("Path requested %q violated KV v2 semantics by dropping /data/", p)
		}
	}
}
