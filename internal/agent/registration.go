// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/primecloud/primecloud-agent/internal/identity"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
	"github.com/primecloud/primecloud-agent/internal/transport"
)

// NodeMetadata collects system attributes from the host machine.
type NodeMetadata struct {
	Hostname      string
	OSName        string
	KernelVersion string
	DockerVersion string
	CPUCoresTotal int32
	MemoryMBTotal int64
	DiskGBTotal   int64
	CertificateCN string
}

// CollectNodeMetadata gathers host and daemon properties for registration.
func CollectNodeMetadata(store *identity.CertificateStore) (*NodeMetadata, error) {
	return ProbeHostMetadata(store, nil), nil
}

// RegistrationManager orchestrates node registration with the Control Plane.
type RegistrationManager struct {
	client *transport.GRPCClient
	store  *identity.CertificateStore
}

// NewRegistrationManager constructs a RegistrationManager.
func NewRegistrationManager(client *transport.GRPCClient, store *identity.CertificateStore) *RegistrationManager {
	return &RegistrationManager{
		client: client,
		store:  store,
	}
}

// RegisterNode initiates the registration handshake over gRPC.
func (r *RegistrationManager) RegisterNode(ctx context.Context, version string) (*pb.RegisterResponse, error) {
	meta, err := CollectNodeMetadata(r.store)
	if err != nil {
		return nil, fmt.Errorf("failed to collect node metadata: %w", err)
	}

	if meta.CertificateCN == "" {
		return nil, fmt.Errorf("%w: missing client certificate identity for registration", ErrRegistrationFailed)
	}

	req := &pb.RegisterRequest{
		AgentVersion:  version,
		CertificateCn: meta.CertificateCN,
		Hostname:      meta.Hostname,
		OsName:        meta.OSName,
		KernelVersion: meta.KernelVersion,
		DockerVersion: meta.DockerVersion,
		CpuCoresTotal: meta.CPUCoresTotal,
		MemoryMbTotal: meta.MemoryMBTotal,
		DiskGbTotal:   meta.DiskGBTotal,
		TimestampUnix: time.Now().Unix(),
	}

	resp, err := r.client.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: grpc register rpc failed: %v", ErrRegistrationFailed, err)
	}

	if !resp.Registered {
		return nil, fmt.Errorf("%w: control plane rejected registration: %s", ErrRegistrationFailed, resp.Message)
	}

	return resp, nil
}
