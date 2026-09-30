package vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

func TestVault_AppRoleLogin_Success(t *testing.T) {
	var loginCalls int32
	var readCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			atomic.AddInt32(&loginCalls, 1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] != "test-role-id" || body["secret_id"] != "test-secret-id" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, `{"errors":["invalid role or secret ID"]}`)
				return
			}
			fmt.Fprintln(w, `{
				"auth": {
					"client_token": "s.agent-token-12345",
					"lease_duration": 3600,
					"renewable": true,
					"policies": ["agent-policy"]
				}
			}`)
		case "/v1/secret/data/primecloud/tenants/proj-1/applications/app-1/env":
			atomic.AddInt32(&readCalls, 1)
			token := r.Header.Get("X-Vault-Token")
			if token != "s.agent-token-12345" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, `{"errors":["permission denied"]}`)
				return
			}
			fmt.Fprintln(w, `{
				"data": {
					"data": {
						"DATABASE_URL": "postgresql://usr:pass@host:5432/db",
						"APP_ENV": "production"
					}
				}
			}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address:  server.URL,
		RoleID:   "test-role-id",
		SecretID: "test-secret-id",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if !client.IsAuthenticated() {
		t.Fatal("expected client to be authenticated after NewClient with AppRole")
	}

	ctx := context.Background()
	data, err := client.ReadSecret(ctx, "secret/data/primecloud/tenants/proj-1/applications/app-1/env")
	if err != nil {
		t.Fatalf("ReadSecret failed: %v", err)
	}

	if data["DATABASE_URL"] != "postgresql://usr:pass@host:5432/db" {
		t.Errorf("unexpected DATABASE_URL: %v", data["DATABASE_URL"])
	}
	if data["APP_ENV"] != "production" {
		t.Errorf("unexpected APP_ENV: %v", data["APP_ENV"])
	}

	if atomic.LoadInt32(&loginCalls) < 1 {
		t.Errorf("expected at least 1 login call, got %d", loginCalls)
	}
	if atomic.LoadInt32(&readCalls) != 1 {
		t.Errorf("expected 1 read call, got %d", readCalls)
	}
}

func TestVault_AppRoleLogin_TokenRenewal(t *testing.T) {
	var loginCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			count := atomic.AddInt32(&loginCalls, 1)
			// Return a very short lease duration (1 second) so it triggers nearExpiry
			fmt.Fprintf(w, `{
				"auth": {
					"client_token": "s.token-attempt-%d",
					"lease_duration": 1,
					"renewable": true,
					"policies": ["agent-policy"]
				}
			}`, count)
		case "/v1/secret/data/test":
			fmt.Fprintln(w, `{"data":{"data":{"key":"val"}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address:  server.URL,
		RoleID:   "role-1",
		SecretID: "secret-1",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	// First read uses initial token
	_, err = client.ReadSecret(ctx, "secret/data/test")
	if err != nil {
		t.Fatalf("First ReadSecret failed: %v", err)
	}

	// Wait 2 seconds for 1-second lease to expire
	time.Sleep(2 * time.Second)

	// Second read must automatically re-authenticate via AppRole
	_, err = client.ReadSecret(ctx, "secret/data/test")
	if err != nil {
		t.Fatalf("Second ReadSecret failed: %v", err)
	}

	if atomic.LoadInt32(&loginCalls) < 2 {
		t.Errorf("expected at least 2 login calls after expiration, got %d", loginCalls)
	}
}

func TestVault_DirectToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := r.Header.Get("X-Vault-Token")
		if token != "s.direct-scoped-token" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"errors":["permission denied"]}`)
			return
		}
		fmt.Fprintln(w, `{
			"data": {
				"data": {
					"SECRET": "direct-success"
				}
			}
		}`)
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
		Token:   "s.direct-scoped-token",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	data, err := client.ReadSecret(ctx, "secret/data/direct")
	if err != nil {
		t.Fatalf("ReadSecret failed: %v", err)
	}

	if data["SECRET"] != "direct-success" {
		t.Errorf("expected SECRET=direct-success, got %v", data["SECRET"])
	}
}

func TestVault_FailClosed_Unauthenticated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Vault server should NOT be called when client is unauthenticated")
	}))
	defer server.Close()

	// No token, no AppRole credentials
	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.ReadSecret(ctx, "secret/data/test")
	if err == nil {
		t.Fatal("expected ReadSecret to fail closed when unauthenticated")
	}

	if !strings.Contains(err.Error(), "unauthenticated") {
		t.Errorf("expected unauthenticated error, got: %v", err)
	}

	err = client.WriteSecret(ctx, "secret/data/test", map[string]interface{}{"a": "b"})
	if err == nil {
		t.Fatal("expected WriteSecret to fail closed when unauthenticated")
	}
}

func TestVault_UnauthorizedPath_Denied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/secret/data/control-plane/admin" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"errors":["1 error occurred: * permission denied"]}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"data":{"data":{"allowed":"yes"}}}`)
	}))
	defer server.Close()

	client, err := vault.NewClient(vault.Config{
		Address: server.URL,
		Token:   "s.agent-scoped-token",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.ReadSecret(ctx, "secret/data/control-plane/admin")
	if err == nil {
		t.Fatal("expected unauthorized path to fail with error")
	}

	if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "403") {
		t.Errorf("expected permission denied error for unauthorized path, got: %v", err)
	}
}
