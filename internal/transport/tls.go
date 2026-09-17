// Package transport provides mTLS configuration, gRPC client connections, and automatic reconnection mechanics.
package transport

import (
	"crypto/tls"
	"fmt"

	"github.com/primecloud/primecloud-agent/internal/identity"
)

// BuildClientTLSConfig creates a strictly authenticated mTLS tls.Config for outbound gRPC connections.
func BuildClientTLSConfig(store *identity.CertificateStore, serverName string) (*tls.Config, error) {
	if store == nil {
		return nil, fmt.Errorf("certificate store cannot be nil")
	}

	clientCert, err := store.LoadTLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	caPool, err := store.LoadCACertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load root/intermediate CA pool: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	return tlsConfig, nil
}

// BuildServerTLSConfig creates an mTLS server configuration requiring client certificate verification.
func BuildServerTLSConfig(store *identity.CertificateStore) (*tls.Config, error) {
	serverCert, err := store.LoadTLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	caPool, err := store.LoadCACertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA pool for client verification: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}
