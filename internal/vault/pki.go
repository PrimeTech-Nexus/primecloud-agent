// Package vault provides client connectivity, PKI certificate issuance, and secret management via HashiCorp Vault.
package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/primecloud/primecloud-agent/internal/agent"
)

// CertificateBundle holds the issued x509 cert, private key, and CA chain in PEM format.
type CertificateBundle struct {
	CertificatePEM string
	PrivateKeyPEM  string
	IssuingCAPEM   string
	CAChainPEM     []string
	SerialNumber   string
	Expiration     time.Time
	ParsedCert     *x509.Certificate
}

// IssueAgentCertificate requests a client/server TLS certificate from Vault PKI.
func (c *Client) IssueAgentCertificate(ctx context.Context, role, commonName string, ipSANs []string, ttl time.Duration) (*CertificateBundle, error) {
	if role == "" {
		role = "agent"
	}
	if commonName == "" {
		return nil, fmt.Errorf("%w: common name is required for certificate issuance", agent.ErrInvalidConfig)
	}

	issuePath := fmt.Sprintf("pki_int/issue/%s", role)
	reqData := map[string]interface{}{
		"common_name": commonName,
	}
	if len(ipSANs) > 0 {
		reqData["ip_sans"] = ipSANs
	}
	if ttl > 0 {
		reqData["ttl"] = ttl.String()
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, issuePath, reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate from %s: %w", issuePath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("vault returned empty data for certificate issuance")
	}

	certPEM, _ := secret.Data["certificate"].(string)
	keyPEM, _ := secret.Data["private_key"].(string)
	caPEM, _ := secret.Data["issuing_ca"].(string)
	serial, _ := secret.Data["serial_number"].(string)

	if certPEM == "" || keyPEM == "" {
		return nil, errors.New("certificate or private key missing in vault response")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM block")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	bundle := &CertificateBundle{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		IssuingCAPEM:   caPEM,
		SerialNumber:   serial,
		Expiration:     parsed.NotAfter,
		ParsedCert:     parsed,
	}

	if chainRaw, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, item := range chainRaw {
			if s, ok := item.(string); ok {
				bundle.CAChainPEM = append(bundle.CAChainPEM, s)
			}
		}
	}

	return bundle, nil
}
