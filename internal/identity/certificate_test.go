package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func generateTestCert(uriStr string, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "pc-node-001",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if uriStr != "" {
		u, err := url.Parse(uriStr)
		if err != nil {
			return nil, err
		}
		template.URIs = []*url.URL{u}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func TestExtractNodeURI_Success(t *testing.T) {
	now := time.Now()
	cert, err := generateTestCert("primecloud://agent/node/001", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	uri, err := ExtractNodeURI(cert)
	if err != nil {
		t.Fatalf("ExtractNodeURI failed unexpectedly: %v", err)
	}
	if uri != "primecloud://agent/node/001" {
		t.Fatalf("Expected primecloud://agent/node/001, got %s", uri)
	}
}

func TestValidateNodeIdentity_Success(t *testing.T) {
	now := time.Now()
	cert, err := generateTestCert("primecloud://agent/node/001", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	if err := ValidateNodeIdentity(cert, "001"); err != nil {
		t.Fatalf("ValidateNodeIdentity failed for matching node ID: %v", err)
	}
}

func TestValidateNodeIdentity_Mismatch(t *testing.T) {
	now := time.Now()
	cert, err := generateTestCert("primecloud://agent/node/002", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	err = ValidateNodeIdentity(cert, "001")
	if err == nil {
		t.Fatal("Expected mismatch error for node 002 vs 001, got nil")
	}
}

func TestValidateNodeIdentity_Expired(t *testing.T) {
	now := time.Now()
	cert, err := generateTestCert("primecloud://agent/node/001", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	err = ValidateNodeIdentity(cert, "001")
	if err == nil {
		t.Fatal("Expected expired certificate error, got nil")
	}
}

func TestExtractNodeURI_MissingURI(t *testing.T) {
	now := time.Now()
	cert, err := generateTestCert("", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	_, err = ExtractNodeURI(cert)
	if err == nil {
		t.Fatal("Expected error for missing URI, got nil")
	}
}
