// Package vault provides client connectivity, PKI certificate issuance, and secret management via HashiCorp Vault.
package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	ErrInvalidConfig    = errors.New("invalid vault configuration")
	ErrVaultUnavailable = errors.New("vault service is unavailable")
	ErrBootstrapFailed  = errors.New("vault bootstrap failed")
)

// Client wraps the official HashiCorp Vault API client.
type Client struct {
	client *vault.Client
	addr   string
}

// Config holds configuration parameters for connecting to Vault.
type Config struct {
	Address string
	Token   string
	Timeout time.Duration
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

	if cfg.Token != "" {
		c.SetToken(cfg.Token)
	}

	client := &Client{
		client: c,
		addr:   cfg.Address,
	}

	return client, nil
}

// RawClient returns the underlying vault.Client pointer.
func (c *Client) RawClient() *vault.Client {
	return c.client
}

// SetToken updates the client token.
func (c *Client) SetToken(token string) {
	c.client.SetToken(token)
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
	_, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return fmt.Errorf("failed to write secret to %s: %w", path, err)
	}
	return nil
}

// ReadSecret reads a secret payload from the specified Vault path.
func (c *Client) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	return secret.Data, nil
}

// DeleteSecret removes a secret at the specified path.
func (c *Client) DeleteSecret(ctx context.Context, path string) error {
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete secret from %s: %w", path, err)
	}
	return nil
}
