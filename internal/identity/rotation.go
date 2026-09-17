// Package identity manages agent x509 certificates, TLS identity files, rotation, and revocation.
package identity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

// RotationManager handles continuous monitoring and rotation of agent identity certificates.
type RotationManager struct {
	store       *CertificateStore
	vaultClient *vault.Client
	logger      *slog.Logger
	role        string
}

// NewRotationManager constructs a RotationManager.
func NewRotationManager(store *CertificateStore, vaultClient *vault.Client, role string, logger *slog.Logger) *RotationManager {
	if role == "" {
		role = "agent"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RotationManager{
		store:       store,
		vaultClient: vaultClient,
		role:        role,
		logger:      logger.With("component", "cert_rotation"),
	}
}

// CheckAndRotate inspects the currently stored certificate and rotates it if half-life is reached.
func (r *RotationManager) CheckAndRotate(ctx context.Context, ttl time.Duration) (bool, error) {
	shouldRotate, err := r.store.ShouldRotate()
	if err != nil {
		return false, fmt.Errorf("failed to check rotation criteria: %w", err)
	}

	if !shouldRotate {
		return false, nil
	}

	r.logger.Info("certificate_rotation_threshold_reached")

	cert, err := r.store.LoadParsedCertificate()
	if err != nil {
		return false, fmt.Errorf("failed to read existing certificate for rotation: %w", err)
	}

	commonName := cert.Subject.CommonName
	ipSANs := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipSANs = append(ipSANs, ip.String())
	}

	newBundle, err := r.vaultClient.IssueAgentCertificate(ctx, r.role, commonName, ipSANs, ttl)
	if err != nil {
		return false, fmt.Errorf("failed to issue renewal certificate from vault: %w", err)
	}

	if err := r.store.SaveBundle(newBundle); err != nil {
		return false, fmt.Errorf("failed to save rotated certificate bundle: %w", err)
	}

	r.logger.Info("certificate_rotation_completed",
		"common_name", commonName,
		"new_expiration", newBundle.Expiration.Format(time.RFC3339),
		"serial", newBundle.SerialNumber,
	)

	return true, nil
}
