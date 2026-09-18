// Package vault provides client connectivity, PKI certificate issuance, and secret management via HashiCorp Vault.
package vault

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// BootstrapManager orchestrates the initial agent node provisioning and PKI bootstrap flow.
type BootstrapManager struct {
	client *Client
}

// NewBootstrapManager constructs a BootstrapManager.
func NewBootstrapManager(client *Client) *BootstrapManager {
	return &BootstrapManager{client: client}
}

// ResolveBootstrapToken reads the bootstrap token from env or token file.
func ResolveBootstrapToken(tokenFromConfig, tokenFilePath string) (string, error) {
	if tokenFromConfig != "" {
		return strings.TrimSpace(tokenFromConfig), nil
	}

	if envToken := os.Getenv("PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN"); envToken != "" {
		return strings.TrimSpace(envToken), nil
	}
	if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
		return strings.TrimSpace(envToken), nil
	}

	if tokenFilePath == "" {
		tokenFilePath = "/etc/primecloud/bootstrap-token"
	}

	data, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return "", fmt.Errorf("%w: bootstrap token not found in env or file %s: %v", ErrBootstrapFailed, tokenFilePath, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%w: bootstrap token file is empty", ErrBootstrapFailed)
	}

	return token, nil
}

// BootstrapNode authenticates with Vault and requests the initial certificate bundle with IP and optional URI SANs.
func (b *BootstrapManager) BootstrapNode(ctx context.Context, commonName string, ipSANs []string, args ...interface{}) (*CertificateBundle, error) {
	healthy, err := b.client.IsHealthy(ctx)
	if err != nil || !healthy {
		return nil, fmt.Errorf("%w: cannot bootstrap, vault is unhealthy: %v", ErrVaultUnavailable, err)
	}

	var uriSANs []string
	var ttl time.Duration = 720 * time.Hour

	for _, arg := range args {
		switch v := arg.(type) {
		case []string:
			uriSANs = v
		case time.Duration:
			ttl = v
		}
	}

	bundle, err := b.client.IssueAgentCertificate(ctx, "agent", commonName, ipSANs, uriSANs, ttl)
	if err != nil {
		return nil, fmt.Errorf("%w: bootstrap certificate issuance failed: %v", ErrBootstrapFailed, err)
	}

	return bundle, nil
}
