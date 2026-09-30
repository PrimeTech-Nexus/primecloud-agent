// Package runtime provides the ContainerRuntime interface and Docker engine abstraction with hardened isolation profiles.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// ContainerRuntime specifies the abstraction contract for container lifecycle on compute nodes.
type ContainerRuntime interface {
	PullImage(ctx context.Context, imageRef string) error
	PullImageWithAuth(ctx context.Context, imageRef string, authBase64 string) error
	CreateContainer(ctx context.Context, cfg *ContainerConfig, limits *ResourceLimits, profile *HardenedIsolationProfile) (string, error)
	StartContainer(ctx context.Context, containerID string) error
	StopContainer(ctx context.Context, containerID string, timeoutSec *int) error
	RemoveContainer(ctx context.Context, containerID string, force bool) error
	InspectContainer(ctx context.Context, containerID string) (*ContainerInspect, error)
	ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error)
	GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error)
	Ping(ctx context.Context) error
	Close() error
}

// DockerRuntime implements ContainerRuntime backed by the official Docker Engine API.
type DockerRuntime struct {
	cli *client.Client
}

// NewDockerRuntime initializes a connection to the Docker daemon.
func NewDockerRuntime() (*DockerRuntime, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	return &DockerRuntime{cli: cli}, nil
}

// Close releases the Docker client connections.
func (d *DockerRuntime) Close() error {
	return d.cli.Close()
}

// Ping verifies connectivity to the Docker daemon.
func (d *DockerRuntime) Ping(ctx context.Context) error {
	_, err := d.cli.Ping(ctx)
	return err
}

// EncodeGHCRAuth formats registry credentials into standard base64url AuthConfig header.
func EncodeGHCRAuth(username, password string) string {
	if password == "" {
		return ""
	}
	if username == "" {
		username = "x-access-token"
	}
	authData, err := registry.EncodeAuthConfig(registry.AuthConfig{
		ServerAddress: "ghcr.io",
		Username:      username,
		Password:      password,
	})
	if err == nil {
		return authData
	}
	return ""
}

// GetGHCRAuth resolves GitHub Container Registry credentials from environment, credential files, or docker config.
func GetGHCRAuth() string {
	u := os.Getenv("GHCR_USERNAME")
	p := os.Getenv("GHCR_TOKEN")
	if p == "" {
		p = os.Getenv("GITHUB_TOKEN")
	}

	// Fallback 1: check provisioned GitHub artifact token file on production node
	if p == "" {
		if tokenBytes, err := os.ReadFile("/etc/primecloud/credentials/github_artifact_token"); err == nil {
			tok := strings.TrimSpace(string(tokenBytes))
			if tok != "" {
				p = tok
			}
		}
	}

	// Fallback 2: check host ~/.docker/config.json or /root/.docker/config.json
	if p == "" {
		dockerConfigPath := "/root/.docker/config.json"
		if home, err := os.UserHomeDir(); err == nil {
			userConfig := filepath.Join(home, ".docker", "config.json")
			if _, err := os.Stat(userConfig); err == nil {
				dockerConfigPath = userConfig
			}
		}
		if data, err := os.ReadFile(dockerConfigPath); err == nil {
			var cfg struct {
				Auths map[string]struct {
					Auth string `json:"auth"`
				} `json:"auths"`
			}
			if err := json.Unmarshal(data, &cfg); err == nil {
				if a, ok := cfg.Auths["ghcr.io"]; ok && a.Auth != "" {
					return a.Auth
				}
				if a, ok := cfg.Auths["https://ghcr.io"]; ok && a.Auth != "" {
					return a.Auth
				}
			}
		}
	}

	if p != "" {
		return EncodeGHCRAuth(u, p)
	}
	return ""
}

// PullImage pulls an image from the container registry (e.g. by tag or digest).
func (d *DockerRuntime) PullImage(ctx context.Context, imageRef string) error {
	authStr := GetGHCRAuth()
	return d.PullImageWithAuth(ctx, imageRef, authStr)
}

// PullImageWithAuth pulls an image using base64-encoded registry authentication.
func (d *DockerRuntime) PullImageWithAuth(ctx context.Context, imageRef string, authBase64 string) error {
	pullOpts := image.PullOptions{}
	if authBase64 != "" {
		pullOpts.RegistryAuth = authBase64
	}
	reader, err := d.cli.ImagePull(ctx, imageRef, pullOpts)
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageRef, err)
	}
	defer reader.Close()
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("failed reading pull response for image %s: %w", imageRef, err)
	}
	return nil
}

// CreateContainer creates a container applying mandatory labels, isolation profile, and resource limits.
func (d *DockerRuntime) CreateContainer(
	ctx context.Context,
	cfg *ContainerConfig,
	limits *ResourceLimits,
	profile *HardenedIsolationProfile,
) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("container config cannot be nil")
	}
	if limits == nil {
		limits = DefaultResourceLimits()
	}
	if profile == nil {
		profile = DefaultHardenedProfile()
	}

	cfg.EnsureMandatoryLabels()

	// 1. Convert environment variables
	envSlice := make([]string, 0, len(cfg.Env))
	for k, v := range cfg.Env {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}

	// 2. Port mappings
	exposedPorts := nat.PortSet{}
	portBindings := nat.PortMap{}
	for cPort, hPort := range cfg.Ports {
		natPort, err := nat.NewPort("tcp", cPort)
		if err == nil {
			exposedPorts[natPort] = struct{}{}
			portBindings[natPort] = []nat.PortBinding{
				{HostIP: "0.0.0.0", HostPort: hPort},
			}
		}
	}

	dockerConfig := &container.Config{
		Image:        cfg.Image,
		Cmd:          cfg.Command,
		Env:          envSlice,
		Labels:       cfg.Labels,
		ExposedPorts: exposedPorts,
	}

	if len(cfg.HealthCheckCmd) > 0 {
		interval := cfg.HealthInterval
		if interval == 0 {
			interval = 5 * time.Second
		}
		timeout := cfg.HealthTimeout
		if timeout == 0 {
			timeout = 3 * time.Second
		}
		retries := cfg.HealthRetries
		if retries == 0 {
			retries = 3
		}
		dockerConfig.Healthcheck = &container.HealthConfig{
			Test:     cfg.HealthCheckCmd,
			Interval: interval,
			Timeout:  timeout,
			Retries:  retries,
		}
	}

	profile.ApplyToContainerConfig(dockerConfig)

	hostConfig := &container.HostConfig{
		Binds:        cfg.Binds,
		PortBindings: portBindings,
	}
	if cfg.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(cfg.NetworkMode)
	}

	limits.ApplyToHostConfig(hostConfig)

	if err := profile.ApplyToHostConfig(hostConfig); err != nil {
		return "", fmt.Errorf("failed to apply security isolation profile: %w", err)
	}

	resp, err := d.cli.ContainerCreate(ctx, dockerConfig, hostConfig, nil, nil, cfg.Name)
	if err != nil {
		return "", fmt.Errorf("failed to create container %s: %w", cfg.Name, err)
	}

	return resp.ID, nil
}

// StartContainer starts a container by ID.
func (d *DockerRuntime) StartContainer(ctx context.Context, containerID string) error {
	return d.cli.ContainerStart(ctx, containerID, container.StartOptions{})
}

// StopContainer stops a running container with graceful timeout.
func (d *DockerRuntime) StopContainer(ctx context.Context, containerID string, timeoutSec *int) error {
	stopOptions := container.StopOptions{}
	if timeoutSec != nil {
		stopOptions.Timeout = timeoutSec
	}
	return d.cli.ContainerStop(ctx, containerID, stopOptions)
}

// RemoveContainer deletes a container.
func (d *DockerRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	return d.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force:         force,
		RemoveVolumes: true,
	})
}

// InspectContainer queries detailed container metadata.
func (d *DockerRuntime) InspectContainer(ctx context.Context, containerID string) (*ContainerInspect, error) {
	inspect, err := d.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	res := &ContainerInspect{
		ID:       inspect.ID,
		Name:     inspect.Name,
		Image:    inspect.Config.Image,
		State:    inspect.State.Status,
		Running:  inspect.State.Running,
		ExitCode: inspect.State.ExitCode,
		Labels:   inspect.Config.Labels,
	}

	if inspect.State.Health != nil {
		res.Health = inspect.State.Health.Status
	}

	if inspect.NetworkSettings != nil {
		res.IPAddress = inspect.NetworkSettings.IPAddress
	}

	if t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil {
		res.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, inspect.State.FinishedAt); err == nil {
		res.FinishedAt = t
	}

	return res, nil
}

// ListContainers returns containers matching criteria.
func (d *DockerRuntime) ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	list, err := d.cli.ContainerList(ctx, container.ListOptions{All: all})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	summaries := make([]ContainerSummary, 0, len(list))
	for _, c := range list {
		summaries = append(summaries, ContainerSummary{
			ID:      c.ID,
			Names:   c.Names,
			Image:   c.Image,
			State:   c.State,
			Status:  c.Status,
			Labels:  c.Labels,
			Created: c.Created,
		})
	}

	return summaries, nil
}

// GetContainerLogs returns a stream of stdout/stderr logs from the container.
func (d *DockerRuntime) GetContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	return d.cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     false,
		Timestamps: true,
	})
}
