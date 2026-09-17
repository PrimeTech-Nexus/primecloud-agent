// Package transport provides mTLS configuration, gRPC client connections, and automatic reconnection mechanics.
package transport

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/primecloud/primecloud-agent/internal/identity"
	pb "github.com/primecloud/primecloud-agent/internal/protocol"
)

// GRPCClient manages the outbound gRPC channel to the Control Plane.
type GRPCClient struct {
	conn       *grpc.ClientConn
	agentpb    pb.AgentServiceClient
	targetAddr string
	store      *identity.CertificateStore
	logger     *slog.Logger
}

// DialOptions contains parameters for establishing the mTLS gRPC channel.
type DialOptions struct {
	TargetAddr string
	ServerName string
	Store      *identity.CertificateStore
	Logger     *slog.Logger
}

// Dial establishes an outbound mTLS gRPC connection.
func Dial(ctx context.Context, opts DialOptions) (*GRPCClient, error) {
	if opts.TargetAddr == "" {
		return nil, fmt.Errorf("target address is required")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("certificate store is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	serverName := opts.ServerName
	if serverName == "" {
		serverName = "primecloud.internal"
	}

	tlsCfg, err := BuildClientTLSConfig(opts.Store, serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to build mTLS client configuration: %w", err)
	}

	creds := credentials.NewTLS(tlsCfg)

	kacp := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(ctx, opts.TargetAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial control plane at %s: %w", opts.TargetAddr, err)
	}

	client := &GRPCClient{
		conn:       conn,
		agentpb:    pb.NewAgentServiceClient(conn),
		targetAddr: opts.TargetAddr,
		store:      opts.Store,
		logger:     opts.Logger.With("component", "grpc_transport"),
	}

	client.logger.Info("grpc_transport_connected", "target", opts.TargetAddr)
	return client, nil
}

// AgentClient returns the protobuf client stub.
func (c *GRPCClient) AgentClient() pb.AgentServiceClient {
	return c.agentpb
}

// Close terminates the gRPC connection.
func (c *GRPCClient) Close() error {
	if c.conn != nil {
		c.logger.Info("grpc_transport_disconnecting", "target", c.targetAddr)
		return c.conn.Close()
	}
	return nil
}

// SendHeartbeat dispatches a single heartbeat to the Control Plane.
func (c *GRPCClient) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return c.agentpb.SendHeartbeat(ctx, req)
}

// Register sends node metadata to register with the Control Plane.
func (c *GRPCClient) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	return c.agentpb.Register(ctx, req)
}
