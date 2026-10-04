// Package runtime provides the ContainerRuntime interface and Docker engine abstraction with hardened isolation profiles.
package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
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
	GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error)
	ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) (stdout []byte, stderr []byte, exitCode int, err error)
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

// Client returns the underlying Docker API client.
func (d *DockerRuntime) Client() *client.Client {
	if d == nil {
		return nil
	}
	return d.cli
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

// GetGHCRAuth resolves GitHub Container Registry credentials from environment, dedicated GHCR credential files, or docker config.
// IMPORTANT: /etc/primecloud/credentials/github_artifact_token is EXCLUSIVELY an installation token for
// the PrimeTech-Nexus/primecloud-agent repository (contents:read) and MUST NOT be used for GHCR container registry pulls.
func GetGHCRAuth() string {
	u := os.Getenv("GHCR_USERNAME")
	if u == "" {
		u = os.Getenv("PRIMECLOUD_GHCR_USERNAME")
	}
	p := os.Getenv("GHCR_TOKEN")
	if p == "" {
		p = os.Getenv("PRIMECLOUD_GHCR_TOKEN")
	}
	if p == "" {
		p = os.Getenv("GITHUB_TOKEN")
	}

	// 1. If username and token are in environment, encode and return
	if p != "" {
		return EncodeGHCRAuth(u, p)
	}

	// 2. Check dedicated GHCR credentials JSON file (/etc/primecloud/credentials/ghcr_auth.json)
	if data, err := os.ReadFile("/etc/primecloud/credentials/ghcr_auth.json"); err == nil {
		var cred struct {
			Username string `json:"username"`
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(data, &cred); err == nil {
			tok := cred.Token
			if tok == "" {
				tok = cred.Password
			}
			if tok != "" {
				user := cred.Username
				if user == "" {
					user = u
				}
				return EncodeGHCRAuth(user, tok)
			}
		}
	}

	// 3. Check dedicated GHCR token file (/etc/primecloud/credentials/ghcr_token)
	if tokenBytes, err := os.ReadFile("/etc/primecloud/credentials/ghcr_token"); err == nil {
		tok := strings.TrimSpace(string(tokenBytes))
		if tok != "" {
			return EncodeGHCRAuth(u, tok)
		}
	}

	// 4. Check host ~/.docker/config.json or /root/.docker/config.json
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

// BuildEnvSlice converts an environment map into Docker's KEY=VALUE string slice.
func BuildEnvSlice(env map[string]string) []string {
	if len(env) == 0 {
		return []string{}
	}
	envSlice := make([]string, 0, len(env))
	for k, v := range env {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}
	return envSlice
}

// BuildPortConfig generates Docker ExposedPorts and HostConfig.PortBindings,
// guaranteeing that container port 8000 (and any specified application ports)
// have an explicit dynamic host port binding (HostIP: "0.0.0.0", HostPort: "").
func BuildPortConfig(ports map[string]string) (nat.PortSet, nat.PortMap, error) {
	exposedPorts := nat.PortSet{}
	portBindings := nat.PortMap{}

	effectivePorts := make(map[string]string)
	for k, v := range ports {
		effectivePorts[k] = v
	}
	if len(effectivePorts) == 0 {
		effectivePorts["8000/tcp"] = ""
	}

	for cPort := range effectivePorts {
		portNum := cPort
		proto := "tcp"
		if parts := strings.Split(cPort, "/"); len(parts) == 2 {
			portNum = parts[0]
			proto = parts[1]
		}
		if portNum == "" {
			portNum = "8000"
		}
		if proto == "" {
			proto = "tcp"
		}

		natPort, err := nat.NewPort(proto, portNum)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid port specification %s: %w", cPort, err)
		}

		exposedPorts[natPort] = struct{}{}
		portBindings[natPort] = []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: "", // Explicitly empty: Docker dynamically allocates an ephemeral host port
			},
		}
	}

	// Guarantee at least 8000/tcp is present
	defaultPort := nat.Port("8000/tcp")
	if _, ok := exposedPorts[defaultPort]; !ok && len(exposedPorts) == 0 {
		exposedPorts[defaultPort] = struct{}{}
		portBindings[defaultPort] = []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: "",
			},
		}
	}

	return exposedPorts, portBindings, nil
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
	envSlice := BuildEnvSlice(cfg.Env)

	// 2. Port mappings
	exposedPorts, portBindings, err := BuildPortConfig(cfg.Ports)
	if err != nil {
		return "", fmt.Errorf("failed to configure port bindings: %w", err)
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
		Ports:    make(map[string]string),
	}

	if inspect.NetworkSettings != nil && inspect.NetworkSettings.Ports != nil {
		for port, bindings := range inspect.NetworkSettings.Ports {
			if len(bindings) > 0 && bindings[0].HostPort != "" {
				res.Ports[string(port)] = bindings[0].HostPort
			}
		}
	}
	if len(res.Ports) == 0 && inspect.HostConfig != nil && inspect.HostConfig.PortBindings != nil {
		for port, bindings := range inspect.HostConfig.PortBindings {
			if len(bindings) > 0 && bindings[0].HostPort != "" {
				res.Ports[string(port)] = bindings[0].HostPort
			}
		}
	}

	if inspect.State.Health != nil {
		res.Health = inspect.State.Health.Status
	}
	res.RestartCount = inspect.RestartCount

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

// GetContainerStats returns a stream of container resource usage statistics.
func (d *DockerRuntime) GetContainerStats(ctx context.Context, containerID string) (io.ReadCloser, error) {
	resp, err := d.cli.ContainerStats(ctx, containerID, false)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ExecContainer executes a command inside a running container with optional environment and stdin.
func (d *DockerRuntime) ExecContainer(ctx context.Context, containerID string, cmd []string, env []string, stdin io.Reader) ([]byte, []byte, int, error) {
	if d.cli == nil {
		return nil, nil, -1, fmt.Errorf("docker client is nil")
	}

	execConfig := types.ExecConfig{
		Cmd:          cmd,
		Env:          env,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  stdin != nil,
	}

	execCreateResp, err := d.cli.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("failed to create container exec for %s: %w", containerID, err)
	}

	attachResp, err := d.cli.ContainerExecAttach(ctx, execCreateResp.ID, types.ExecStartCheck{})
	if err != nil {
		return nil, nil, -1, fmt.Errorf("failed to attach to container exec: %w", err)
	}
	defer attachResp.Close()

	if stdin != nil {
		go func() {
			_, _ = io.Copy(attachResp.Conn, stdin)
			_ = attachResp.CloseWrite()
		}()
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, attachResp.Reader)
	if err != nil && err != io.EOF {
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), -1, fmt.Errorf("failed reading exec stream: %w", err)
	}

	inspectResp, err := d.cli.ContainerExecInspect(ctx, execCreateResp.ID)
	if err != nil {
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), 0, nil
	}

	return stdoutBuf.Bytes(), stderrBuf.Bytes(), inspectResp.ExitCode, nil
}

