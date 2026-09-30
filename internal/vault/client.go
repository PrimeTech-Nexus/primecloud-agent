// Package vault provides client connectivity, PKI certificate issuance, and secret management via HashiCorp Vault.
package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	ErrInvalidConfig    = errors.New("invalid vault configuration")
	ErrVaultUnavailable = errors.New("vault service is unavailable")
	ErrBootstrapFailed  = errors.New("vault bootstrap failed")
	ErrUnauthenticated  = errors.New("vault client is unauthenticated")
)

// Client wraps the official HashiCorp Vault API client with AppRole auto-authentication and token management.
type Client struct {
	client         *vault.Client
	addr           string
	roleID         string
	secretID       string
	tokenExpiresAt time.Time
	mu             sync.Mutex
}

// Config holds configuration parameters for connecting to Vault.
type Config struct {
	Address  string
	Token    string
	RoleID   string
	SecretID string
	Timeout  time.Duration
}

// NewClient initializes a new Vault client and validates connectivity.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("%w: vault address is empty", ErrInvalidConfig)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	vConfig := vault.DefaultConfig()
	vConfig.Address = cfg.Address
	vConfig.Timeout = cfg.Timeout

	c, err := vault.NewClient(vConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create vault client: %v", ErrVaultUnavailable, err)
	}

	client := &Client{
		client:   c,
		addr:     cfg.Address,
		roleID:   strings.TrimSpace(cfg.RoleID),
		secretID: strings.TrimSpace(cfg.SecretID),
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	} else if client.roleID != "" && client.secretID != "" {
		// Attempt initial AppRole authentication
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
		_ = client.AppRoleLogin(ctx, client.roleID, client.secretID)
	}

	return client, nil
}

// RawClient returns the underlying vault.Client pointer.
func (c *Client) RawClient() *vault.Client {
	return c.client
}

// SetToken updates the client token.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client.SetToken(strings.TrimSpace(token))
	c.tokenExpiresAt = time.Now().Add(720 * time.Hour)
}

// Token returns the current client token.
func (c *Client) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client.Token()
}

// IsAuthenticated reports whether the client has an active token.
func (c *Client) IsAuthenticated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client.Token() != ""
}

// AppRoleLogin authenticates against Vault using the AppRole method and updates the client token.
func (c *Client) AppRoleLogin(ctx context.Context, roleID, secretID string) error {
	rID := strings.TrimSpace(roleID)
	sID := strings.TrimSpace(secretID)
	if rID == "" || sID == "" {
		return fmt.Errorf("%w: role_id and secret_id must not be empty", ErrInvalidConfig)
	}

	data := map[string]interface{}{
		"role_id":   rID,
		"secret_id": sID,
	}

	resp, err := c.client.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("approle authentication failed: %w", err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return errors.New("approle authentication returned empty client token")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.client.SetToken(resp.Auth.ClientToken)
	c.roleID = rID
	c.secretID = sID
	if resp.Auth.LeaseDuration > 0 {
		c.tokenExpiresAt = time.Now().Add(time.Duration(resp.Auth.LeaseDuration) * time.Second)
	} else {
		c.tokenExpiresAt = time.Now().Add(1 * time.Hour)
	}

	return nil
}

// EnsureAuthenticated ensures the client has an active, valid token, re-authenticating via AppRole if necessary.
func (c *Client) EnsureAuthenticated(ctx context.Context) error {
	c.mu.Lock()
	hasToken := c.client.Token() != ""
	hasAppRole := c.roleID != "" && c.secretID != ""
	nearExpiry := hasAppRole && time.Now().Add(1*time.Minute).After(c.tokenExpiresAt)
	roleID := c.roleID
	secretID := c.secretID
	c.mu.Unlock()

	if hasAppRole && (!hasToken || nearExpiry) {
		return c.AppRoleLogin(ctx, roleID, secretID)
	}

	if !hasToken {
		return fmt.Errorf("%w: no token or valid approle credentials configured", ErrUnauthenticated)
	}

	return nil
}

// IsHealthy checks if the Vault instance is reachable, initialized, and unsealed.
func (c *Client) IsHealthy(ctx context.Context) (bool, error) {
	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: health check error: %v", ErrVaultUnavailable, err)
	}
	if !health.Initialized || health.Sealed {
		return false, fmt.Errorf("%w: vault unready (initialized=%v, sealed=%v)", ErrVaultUnavailable, health.Initialized, health.Sealed)
	}
	return true, nil
}

// WriteSecret writes a secret payload to the specified Vault path.
func (c *Client) WriteSecret(ctx context.Context, path string, data map[string]interface{}) error {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return fmt.Errorf("vault write error: %w", err)
	}

	payload := data
	if strings.Contains(path, "/data/") {
		if _, hasData := data["data"]; !hasData {
			payload = map[string]interface{}{"data": data}
		}
	}
	_, err := c.client.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return fmt.Errorf("failed to write secret to %s: %w", path, err)
	}
	return nil
}

// ReadSecret reads a secret payload from the specified Vault path.
func (c *Client) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("vault read error: %w", err)
	}

	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	if nested, ok := secret.Data["data"].(map[string]interface{}); ok {
		return nested, nil
	}
	return secret.Data, nil
}

// DeleteSecret removes a secret at the specified path.
func (c *Client) DeleteSecret(ctx context.Context, path string) error {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return fmt.Errorf("vault delete error: %w", err)
	}

	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete secret from %s: %w", path, err)
	}
	return nil
}
