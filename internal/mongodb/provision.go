// Package mongodb provides the authoritative MongoDB driver for provisioning, rs0 replica set bootstrap, credentials, lifecycle, backup, and restore.
package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/primecloud/primecloud-agent/internal/applications"
	"github.com/primecloud/primecloud-agent/internal/network"
	"github.com/primecloud/primecloud-agent/internal/runtime"
	"github.com/primecloud/primecloud-agent/internal/vault"
)

const (
	// DefaultPort is the canonical internal MongoDB port.
	DefaultPort = 27017
	// DefaultReplicaSet is the canonical single-node replica set name.
	DefaultReplicaSet = "rs0"
	// DefaultImage is the default version-pinned official MongoDB image.
	DefaultImage = "mongo:7.0"
)

// Credentials holds generated MongoDB connection and role-based auth properties.
type Credentials struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	Database      string `json:"database"`
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`
	ReplicaSet    string `json:"replica_set"`
	Port          int    `json:"port"`
}

// ProvisionResult contains details of the provisioned MongoDB instance.
type ProvisionResult struct {
	ResourceID     string       `json:"resource_id"`
	ContainerID    string       `json:"container_id"`
	Endpoint       string       `json:"endpoint"`
	ReplicaSet     string       `json:"replica_set"`
	VaultSecretRef string       `json:"vault_secret_ref"`
	VolumePath     string       `json:"volume_path"`
	Credentials    *Credentials `json:"-"` // Redacted from JSON output
}

// Provisioner orchestrates MongoDB provisioning and single-node rs0 replica set bootstrap on compute nodes.
type Provisioner struct {
	rt          runtime.ContainerRuntime
	vaultClient *vault.Client
	baseResDir  string
	netMgr      *network.Manager
	logger      *slog.Logger
}

// NewProvisioner constructs a Provisioner instance.
func NewProvisioner(rt runtime.ContainerRuntime, vaultClient *vault.Client, baseResDir string, logger *slog.Logger) *Provisioner {
	if baseResDir == "" {
		baseResDir = "/opt/primecloud/resources"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{
		rt:          rt,
		vaultClient: vaultClient,
		baseResDir:  baseResDir,
		logger:      logger.With("component", "mongodb_provisioner"),
	}
}

// SetNetworkManager sets the ManagedDataNetworkManager for network attachment.
func (p *Provisioner) SetNetworkManager(mgr *network.Manager) {
	p.netMgr = mgr
}

// ResolvePinnedImage maps a version or image string to a version-pinned official MongoDB image ("mongo:6.0" or "mongo:7.0").
func ResolvePinnedImage(versionOrImage string) (string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(versionOrImage))
	if trimmed == "" || trimmed == "7.0" || trimmed == "mongo:7.0" {
		return "mongo:7.0", nil
	}
	if trimmed == "6.0" || trimmed == "mongo:6.0" {
		return "mongo:6.0", nil
	}
	if strings.HasPrefix(trimmed, "7.0.") || strings.HasPrefix(trimmed, "mongo:7.0.") {
		return "mongo:7.0", nil
	}
	if strings.HasPrefix(trimmed, "6.0.") || strings.HasPrefix(trimmed, "mongo:6.0.") {
		return "mongo:6.0", nil
	}
	return "", fmt.Errorf("UNSUPPORTED_MONGODB_VERSION: unsupported MongoDB version or image %q (allowed: 6.0, 7.0)", versionOrImage)
}

// GenerateCredentials produces cryptographically secure admin and scoped tenant credentials.
func GenerateCredentials(resourceID string) (*Credentials, error) {
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random tenant password: %w", err)
	}
	adminBytes := make([]byte, 16)
	if _, err := rand.Read(adminBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random admin password: %w", err)
	}

	sanitizedID := stringsFilterAlpha(resourceID)
	if len(sanitizedID) > 8 {
		sanitizedID = sanitizedID[:8]
	}

	return &Credentials{
		Username:      fmt.Sprintf("pc_user_%s", sanitizedID),
		Password:      hex.EncodeToString(pwBytes),
		Database:      fmt.Sprintf("pc_db_%s", sanitizedID),
		AdminUsername: "admin",
		AdminPassword: hex.EncodeToString(adminBytes),
		ReplicaSet:    DefaultReplicaSet,
		Port:          DefaultPort,
	}, nil
}

func generateKeyfileSecret() (string, error) {
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Provision prepares storage, generates credentials, writes them to Vault, starts the container, and bootstraps rs0.
func (p *Provisioner) Provision(ctx context.Context, resourceID, image string, hostPort string) (*ProvisionResult, error) {
	return p.ProvisionWithProject(ctx, "default", "", resourceID, image, hostPort)
}

// ProvisionWithProject prepares storage, generates credentials, writes them to Vault under the tenant path, starts the container, and bootstraps rs0.
func (p *Provisioner) ProvisionWithProject(ctx context.Context, projectID, environmentID, resourceID, image, hostPort string) (*ProvisionResult, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id cannot be empty")
	}
	if projectID == "" {
		projectID = "default"
	}

	pinnedImage, err := ResolvePinnedImage(image)
	if err != nil {
		return nil, err
	}

	p.logger.Info("provisioning_mongodb_starting", "project_id", projectID, "resource_id", resourceID, "image", pinnedImage)

	// 1. Create Volume Directory and internal cluster auth keyfile (UID 999:999)
	volumePath := filepath.Join(p.baseResDir, "mongodb", resourceID)
	kfSecret, err := generateKeyfileSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate mongodb keyfile secret: %w", err)
	}
	dataDir, keyfilePath, err := ensureMongoDBDataDir(volumePath, kfSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb volume directory %s: %w", volumePath, err)
	}

	// 2. Generate Credentials
	creds, err := GenerateCredentials(resourceID)
	if err != nil {
		return nil, err
	}

	legacyHost := fmt.Sprintf("pc-mg-%s", resourceID)
	internalHost := fmt.Sprintf("mongodb-%s.internal.primecloud", resourceID)

	urlHost := internalHost
	if environmentID == "" {
		urlHost = legacyHost
	}
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/%s?authSource=%s&replicaSet=%s",
		creds.Username, creds.Password, urlHost, creds.Port, creds.Database, creds.Database, creds.ReplicaSet)

	// 3. Store Credentials in Vault
	tenantVaultRef := fmt.Sprintf("secret/data/primecloud/tenants/%s/mongodb/%s", projectID, resourceID)
	compatVaultRef := fmt.Sprintf("primecloud/resources/mongodb/%s", resourceID)
	if p.vaultClient != nil {
		secretData := map[string]interface{}{
			"username":       creds.Username,
			"password":       creds.Password,
			"database":       creds.Database,
			"admin_username": creds.AdminUsername,
			"admin_password": creds.AdminPassword,
			"root_password":  creds.AdminPassword,
			"replica_set":    creds.ReplicaSet,
			"host":           legacyHost,
			"port":           creds.Port,
			"uri":            uri,
			"url":            uri,
		}
		if err := p.vaultClient.WriteSecret(ctx, tenantVaultRef, secretData); err != nil {
			return nil, fmt.Errorf("failed to store mongodb credentials in vault (%s): %w", tenantVaultRef, err)
		}
		p.logger.Info("mongodb_credentials_stored_in_vault", "vault_ref", tenantVaultRef)

		if err := p.vaultClient.WriteSecret(ctx, compatVaultRef, secretData); err != nil {
			p.logger.Warn("mongodb_credentials_compat_vault_write_failed", "vault_ref", compatVaultRef, "error", err)
		}
	}

	// 4. Container Configuration with --replSet rs0 --auth --keyFile
	containerName := fmt.Sprintf("pc-mg-%s", resourceID)
	cfg := &runtime.ContainerConfig{
		Name:  containerName,
		Image: pinnedImage,
		Command: []string{
			"mongod",
			"--replSet", DefaultReplicaSet,
			"--bind_ip_all",
			"--auth",
			"--keyFile", "/etc/mongo/mongo-keyfile",
		},
		Env: map[string]string{
			"MONGO_INITDB_ROOT_USERNAME": creds.AdminUsername,
			"MONGO_INITDB_ROOT_PASSWORD": creds.AdminPassword,
			"MONGO_INITDB_DATABASE":      creds.Database,
		},
		Binds: []string{
			fmt.Sprintf("%s:/data/db:rw", dataDir),
			fmt.Sprintf("%s:/etc/mongo/mongo-keyfile:ro", keyfilePath),
		},
		HealthCheckCmd: []string{
			"CMD",
			"mongosh",
			"--quiet",
			"-u", creds.AdminUsername,
			"-p", creds.AdminPassword,
			"--authenticationDatabase", "admin",
			"--eval", "db.adminCommand({ ping: 1 }).ok",
		},
		HealthInterval: 3 * time.Second,
		HealthTimeout:  2 * time.Second,
		HealthRetries:  10,
		Labels: map[string]string{
			"primecloud.resource_id": resourceID,
			"primecloud.engine":      "mongodb",
			"primecloud.managed":     "true",
		},
		WorkloadType: runtime.WorkloadTypeManagedMongoDB,
	}

	if hostPort != "" {
		cfg.Ports = map[string]string{
			"27017": hostPort,
		}
	}

	limits := runtime.DefaultResourceLimits()
	profile := runtime.DefaultHardenedProfile()
	profile.User = "999:999"

	var containerID string
	if p.rt != nil {
		if err := p.rt.PullImage(ctx, pinnedImage); err != nil {
			p.logger.Warn("image_pull_attempt_failed_proceeding", "image", pinnedImage, "error", err)
		}
		cid, err := p.rt.CreateContainer(ctx, cfg, limits, profile)
		if err != nil {
			return nil, fmt.Errorf("failed to create mongodb container: %w", err)
		}
		containerID = cid

		if err := p.rt.StartContainer(ctx, containerID); err != nil {
			_ = p.rt.RemoveContainer(ctx, containerID, true)
			return nil, fmt.Errorf("failed to start mongodb container: %w", err)
		}

		// Attach container to pc-net-<environmentID> before rs.initiate so internal DNS resolves
		if p.netMgr != nil && environmentID != "" {
			aliases := network.FormatMongoDBAliases(resourceID)
			if err := p.netMgr.AttachContainerToEnvironmentNetwork(ctx, environmentID, containerID, aliases); err != nil {
				p.logger.Warn("mongodb_network_attach_failed",
					"resource_id", resourceID,
					"environment_id", environmentID,
					"container_id", containerID,
					"error", err,
				)
			} else {
				p.logger.Info("mongodb_network_attached",
					"resource_id", resourceID,
					"environment_id", environmentID,
					"network", "pc-net-"+environmentID,
					"aliases", aliases,
				)
			}
		}

		if err := applications.WaitForContainerReady(ctx, p.rt, containerID, 45*time.Second); err != nil {
			return nil, fmt.Errorf("mongodb container failed health check: %w", err)
		}

		// 5. Idempotent single-node replica set (rs0) bootstrap and scoped tenant user creation
		if err := p.bootstrapReplicaSetAndTenantUser(ctx, containerID, creds); err != nil {
			return nil, fmt.Errorf("failed to bootstrap mongodb rs0 and tenant user: %w", err)
		}
	}

	result := &ProvisionResult{
		ResourceID:     resourceID,
		ContainerID:    containerID,
		Endpoint:       fmt.Sprintf("%s:27017", legacyHost),
		ReplicaSet:     DefaultReplicaSet,
		VaultSecretRef: tenantVaultRef,
		VolumePath:     volumePath,
		Credentials:    creds,
	}

	p.logger.Info("provisioning_mongodb_completed", "resource_id", resourceID, "endpoint", result.Endpoint, "replica_set", DefaultReplicaSet)
	return result, nil
}

// bootstrapReplicaSetAndTenantUser idempotently initializes single-node replica set rs0 and creates the scoped tenant user.
func (p *Provisioner) bootstrapReplicaSetAndTenantUser(ctx context.Context, containerID string, creds *Credentials) error {
	js := fmt.Sprintf(`
try {
    var st = rs.status();
} catch (e) {
    rs.initiate({ _id: %q, members: [{ _id: 0, host: "127.0.0.1:27017" }] });
}
var dbRef = db.getSiblingDB(%q);
var existing = dbRef.getUser(%q);
if (!existing) {
    dbRef.createUser({
        user: %q,
        pwd: %q,
        roles: [
            { role: "readWrite", db: %q },
            { role: "dbAdmin", db: %q }
        ]
    });
}
`, creds.ReplicaSet, creds.Database, creds.Username, creds.Username, creds.Password, creds.Database, creds.Database)

	cmd := []string{
		"mongosh",
		"--quiet",
		"-u", creds.AdminUsername,
		"-p", creds.AdminPassword,
		"--authenticationDatabase", "admin",
		"--eval", js,
	}
	_, stderr, exitCode, err := p.rt.ExecContainer(ctx, containerID, cmd, nil, nil)
	if err != nil {
		return fmt.Errorf("mongosh bootstrap exec failed: %w (stderr: %s)", err, string(stderr))
	}
	if exitCode != 0 {
		return fmt.Errorf("mongosh bootstrap exited with code %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}
	return nil
}

// SetHostPort reconfigures the MongoDB container with a new published host port while preserving the persistent data volume.
func (p *Provisioner) SetHostPort(ctx context.Context, projectID, environmentID, resourceID string, hostPort string) error {
	if resourceID == "" {
		return fmt.Errorf("resource_id cannot be empty")
	}
	if projectID == "" {
		projectID = "default"
	}

	containerName := fmt.Sprintf("pc-mg-%s", resourceID)
	volumePath := filepath.Join(p.baseResDir, "mongodb", resourceID)
	dataDir := filepath.Join(volumePath, "data")
	keyfilePath := filepath.Join(volumePath, "mongo-keyfile")

	image := DefaultImage
	var creds *Credentials
	if p.vaultClient != nil {
		if c, err := resolveMongoDBCredentials(ctx, p.vaultClient, projectID, resourceID); err == nil && c != nil {
			creds = c
		}
	}
	if creds == nil {
		if p.rt != nil {
			if insp, err := p.rt.InspectContainer(ctx, containerName); err == nil && insp != nil && insp.Image != "" {
				image = insp.Image
			}
		}
		sanitizedID := stringsFilterAlpha(resourceID)
		if len(sanitizedID) > 8 {
			sanitizedID = sanitizedID[:8]
		}
		creds = &Credentials{
			Username:      fmt.Sprintf("pc_user_%s", sanitizedID),
			Database:      fmt.Sprintf("pc_db_%s", sanitizedID),
			AdminUsername: "admin",
			ReplicaSet:    DefaultReplicaSet,
			Port:          DefaultPort,
		}
	}

	cfg := &runtime.ContainerConfig{
		Name:  containerName,
		Image: image,
		Command: []string{
			"mongod",
			"--replSet", DefaultReplicaSet,
			"--bind_ip_all",
			"--auth",
			"--keyFile", "/etc/mongo/mongo-keyfile",
		},
		Env: map[string]string{
			"MONGO_INITDB_ROOT_USERNAME": creds.AdminUsername,
			"MONGO_INITDB_ROOT_PASSWORD": creds.AdminPassword,
			"MONGO_INITDB_DATABASE":      creds.Database,
		},
		Binds: []string{
			fmt.Sprintf("%s:/data/db:rw", dataDir),
			fmt.Sprintf("%s:/etc/mongo/mongo-keyfile:ro", keyfilePath),
		},
		HealthCheckCmd: []string{
			"CMD",
			"mongosh",
			"--quiet",
			"-u", creds.AdminUsername,
			"-p", creds.AdminPassword,
			"--authenticationDatabase", "admin",
			"--eval", "db.adminCommand({ ping: 1 }).ok",
		},
		HealthInterval: 3 * time.Second,
		HealthTimeout:  2 * time.Second,
		HealthRetries:  10,
		Labels: map[string]string{
			"primecloud.resource_id": resourceID,
			"primecloud.engine":      "mongodb",
			"primecloud.managed":     "true",
		},
		WorkloadType: runtime.WorkloadTypeManagedMongoDB,
	}

	if hostPort != "" {
		cfg.Ports = map[string]string{
			"27017": hostPort,
		}
	}

	limits := runtime.DefaultResourceLimits()
	profile := runtime.DefaultHardenedProfile()
	profile.User = "999:999"

	if p.rt == nil {
		return fmt.Errorf("container runtime is nil")
	}

	timeout := 10
	_ = p.rt.StopContainer(ctx, containerName, &timeout)
	_ = p.rt.RemoveContainer(ctx, containerName, true)

	cid, err := p.rt.CreateContainer(ctx, cfg, limits, profile)
	if err != nil {
		return fmt.Errorf("failed to recreate mongodb container: %w", err)
	}
	if err := p.rt.StartContainer(ctx, cid); err != nil {
		return fmt.Errorf("failed to start recreated mongodb container: %w", err)
	}
	if err := applications.WaitForContainerReady(ctx, p.rt, cid, 45*time.Second); err != nil {
		return fmt.Errorf("recreated mongodb container failed health check: %w", err)
	}

	if p.netMgr != nil && environmentID != "" {
		aliases := network.FormatMongoDBAliases(resourceID)
		_ = p.netMgr.AttachContainerToEnvironmentNetwork(ctx, environmentID, cid, aliases)
	}

	return nil
}

func stringsFilterAlpha(s string) string {
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		}
	}
	return string(out)
}
