// Package identity manages agent x509 certificates, TLS identity files, rotation, and revocation.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/primecloud/primecloud-agent/internal/vault"
)

const (
	CertFileName = "agent.crt"
	KeyFileName  = "agent.key"
	CAFileName   = "ca.crt"
)

// CertificateStore handles saving and loading x509 certificates and keys on disk.
type CertificateStore struct {
	baseDir string
}

// NewCertificateStore constructs a CertificateStore targeting the specified directory.
func NewCertificateStore(baseDir string) (*CertificateStore, error) {
	if baseDir == "" {
		baseDir = "/etc/primecloud/agent"
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create certificate directory %s: %w", baseDir, err)
	}
	return &CertificateStore{baseDir: baseDir}, nil
}

// SaveBundle saves certificate, private key, and CA files with strict file permissions.
func (s *CertificateStore) SaveBundle(bundle *vault.CertificateBundle) error {
	if bundle == nil {
		return errors.New("cannot save nil certificate bundle")
	}

	certPath := filepath.Join(s.baseDir, CertFileName)
	keyPath := filepath.Join(s.baseDir, KeyFileName)
	caPath := filepath.Join(s.baseDir, CAFileName)

	// Save private key with 0600 permissions
	if err := os.WriteFile(keyPath, []byte(bundle.PrivateKeyPEM), 0600); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", keyPath, err)
	}

	// Save cert with 0644 permissions
	if err := os.WriteFile(certPath, []byte(bundle.CertificatePEM), 0644); err != nil {
		return fmt.Errorf("failed to write certificate to %s: %w", certPath, err)
	}

	// Save CA chain if present
	caContent := bundle.IssuingCAPEM
	if len(bundle.CAChainPEM) > 0 {
		for _, c := range bundle.CAChainPEM {
			caContent += "\n" + c
		}
	}
	if caContent != "" {
		if err := os.WriteFile(caPath, []byte(caContent), 0644); err != nil {
			return fmt.Errorf("failed to write CA certificate to %s: %w", caPath, err)
		}
	}

	return nil
}

// LoadTLSCertificate loads the client certificate pair into a tls.Certificate.
func (s *CertificateStore) LoadTLSCertificate() (tls.Certificate, error) {
	certPath := filepath.Join(s.baseDir, CertFileName)
	keyPath := filepath.Join(s.baseDir, KeyFileName)
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// LoadParsedCertificate loads and parses the x509 leaf certificate.
func (s *CertificateStore) LoadParsedCertificate() (*x509.Certificate, error) {
	certPath := filepath.Join(s.baseDir, CertFileName)
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate from %s: %w", certPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	return cert, nil
}

// LoadCACertPool loads the issuing CA bundle into an x509.CertPool.
func (s *CertificateStore) LoadCACertPool() (*x509.CertPool, error) {
	caPath := filepath.Join(s.baseDir, CAFileName)
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file from %s: %w", caPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("failed to append CA certificates to pool")
	}
	return pool, nil
}

// IsExpired checks if the stored certificate has expired.
func (s *CertificateStore) IsExpired() (bool, error) {
	cert, err := s.LoadParsedCertificate()
	if err != nil {
		return false, err
	}
	return time.Now().After(cert.NotAfter), nil
}

// ShouldRotate checks if certificate has passed 50% of its total TTL.
func (s *CertificateStore) ShouldRotate() (bool, error) {
	cert, err := s.LoadParsedCertificate()
	if err != nil {
		return false, err
	}

	totalDuration := cert.NotAfter.Sub(cert.NotBefore)
	halfLife := cert.NotBefore.Add(totalDuration / 2)

	return time.Now().After(halfLife), nil
}

// CertPaths returns absolute paths to cert, key, and CA.
func (s *CertificateStore) CertPaths() (string, string, string) {
	return filepath.Join(s.baseDir, CertFileName),
		filepath.Join(s.baseDir, KeyFileName),
		filepath.Join(s.baseDir, CAFileName)
}

// ExtractNodeURI extracts the authoritative URI SAN in the format primecloud://agent/node/<node-id>.
func ExtractNodeURI(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("cannot extract URI from nil certificate")
	}
	for _, uri := range cert.URIs {
		if uri != nil && len(uri.String()) > 0 {
			uriStr := uri.String()
			if filepath.Clean(uriStr) != "" && (uri.Scheme == "primecloud" && uri.Host == "agent") {
				return uriStr, nil
			}
		}
	}
	return "", fmt.Errorf("no valid primecloud://agent/node/<node-id> URI SAN found in certificate")
}

// ValidateNodeIdentity verifies that the certificate contains the expected node URI and is valid.
func ValidateNodeIdentity(cert *x509.Certificate, expectedNodeID string) error {
	if cert == nil {
		return errors.New("cannot validate nil certificate")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return errors.New("certificate has expired")
	}
	uri, err := ExtractNodeURI(cert)
	if err != nil {
		return err
	}
	expectedURI := fmt.Sprintf("primecloud://agent/node/%s", expectedNodeID)
	if uri != expectedURI {
		return fmt.Errorf("certificate URI identity mismatch: got %s, expected %s", uri, expectedURI)
	}
	return nil
}
