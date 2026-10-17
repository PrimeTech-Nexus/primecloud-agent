// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents runtime configuration parameters for the PrimeCloud Agent daemon.
type Config struct {
	ConfigFile          string        `json:"config_file"`
	NodeID              string        `json:"node_id"`
	AgentID             string        `json:"agent_id"`
	AgentKey            string        `json:"-"` // Shared cluster agent secret (never serialized in JSON)
	ControlPlaneURL     string        `json:"control_plane_url"`
	ControlPlaneHTTPURL string        `json:"control_plane_http_url"`
	QueueURL            string        `json:"queue_url"`
	VaultAddr           string        `json:"vault_addr"`
	VaultRoleID         string        `json:"-"` // Never serialized in JSON
	VaultSecretID       string        `json:"-"` // Never serialized in JSON
	BootstrapToken      string        `json:"-"` // Never serialized in JSON
	CertDir             string        `json:"cert_dir"`
	ResourceDir         string        `json:"resource_dir"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`
	LogLevel            slog.Level    `json:"log_level"`
	DockerHost          string        `json:"docker_host"`
	ShellListenAddr     string        `json:"shell_listen_addr"` // e.g. ":50052" for incoming gRPC shell streaming
	ReconcileInterval   time.Duration `json:"reconcile_interval"`
	RotationCheckPeriod time.Duration `json:"rotation_check_period"`
}

// String implements fmt.Stringer to ensure secrets are never leaked in string formatting.
func (c *Config) String() string {
	return fmt.Sprintf("Config{NodeID:%s, AgentID:%s, ControlPlaneURL:%s, ControlPlaneHTTPURL:%s, QueueURL:%s, VaultAddr:%s, CertDir:%s, ResourceDir:%s, HeartbeatInterval:%v, LogLevel:%v, DockerHost:%s}",
		c.NodeID, c.AgentID, c.ControlPlaneURL, c.ControlPlaneHTTPURL, c.QueueURL, c.VaultAddr, c.CertDir, c.ResourceDir, c.HeartbeatInterval, c.LogLevel, c.DockerHost)
}

// DefaultConfig returns baseline configuration defaults.
func DefaultConfig() *Config {
	return &Config{
		ConfigFile:          "/etc/primecloud/agent.yaml",
		NodeID:              "0191c001-0000-7000-8000-000000000001",
		AgentID:             "agent-node-0191c001-0000-7000-8000-000000000001",
		ControlPlaneURL:     "127.0.0.1:50051",
		ControlPlaneHTTPURL: "http://127.0.0.1:8000",
		QueueURL:            "127.0.0.1:6379",
		VaultAddr:           "http://127.0.0.1:8200",
		CertDir:             "/etc/primecloud/agent",
		ResourceDir:         "/opt/primecloud/resources",
		HeartbeatInterval:   10 * time.Second,
		LogLevel:            slog.LevelInfo,
		DockerHost:          "",
		ReconcileInterval:   30 * time.Second,
		RotationCheckPeriod: 5 * time.Minute,
	}
}

// LoadConfig loads configuration from environment variables and an optional file.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// 1. Check custom config file path from env
	if envPath := os.Getenv("PRIMECLOUD_AGENT_CONFIG_FILE"); envPath != "" {
		cfg.ConfigFile = envPath
	}

	// 2. Read environment variables (take precedence over defaults)
	if v := os.Getenv("PRIMECLOUD_AGENT_NODE_ID"); v != "" {
		cfg.NodeID = v
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_ID"); v != "" {
		cfg.AgentID = v
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_SHARED_KEY"); v != "" {
		cfg.AgentKey = strings.TrimSpace(v)
	} else if v := os.Getenv("PRIMECLOUD_AGENT_KEY"); v != "" {
		cfg.AgentKey = strings.TrimSpace(v)
	} else if keyBytes, err := os.ReadFile("/etc/primecloud/credentials/agent_shared_key"); err == nil {
		cfg.AgentKey = strings.TrimSpace(string(keyBytes))
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_CONTROL_PLANE_URL"); v != "" {
		cfg.ControlPlaneURL = v
	}
	var explicitHTTPURL string
	if v := os.Getenv("PRIMECLOUD_AGENT_CONTROL_PLANE_HTTP_URL"); v != "" {
		explicitHTTPURL = strings.TrimSpace(v)
	} else if v := os.Getenv("PRIMECLOUD_CONTROL_PLANE_HTTP_URL"); v != "" {
		explicitHTTPURL = strings.TrimSpace(v)
	} else if v := os.Getenv("PRIMECLOUD_CONTROL_PLANE_URL"); v != "" && (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")) {
		explicitHTTPURL = strings.TrimSpace(v)
	}

	if explicitHTTPURL != "" {
		if !strings.HasPrefix(explicitHTTPURL, "http://") && !strings.HasPrefix(explicitHTTPURL, "https://") {
			explicitHTTPURL = "http://" + explicitHTTPURL
		}
		cfg.ControlPlaneHTTPURL = explicitHTTPURL
	} else if v := os.Getenv("PRIMECLOUD_AGENT_CONTROL_PLANE_URL"); v != "" {
		// ControlPlaneURL was overridden via env, derive ControlPlaneHTTPURL from it
		derived := cfg.ControlPlaneURL
		if strings.Contains(derived, ":50051") {
			derived = strings.Replace(derived, ":50051", ":8000", 1)
		}
		if !strings.HasPrefix(derived, "http://") && !strings.HasPrefix(derived, "https://") {
			derived = "http://" + derived
		}
		cfg.ControlPlaneHTTPURL = derived
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_SHELL_LISTEN_ADDR"); v != "" {
		cfg.ShellListenAddr = strings.TrimSpace(v)
	}
	if v := os.Getenv("PRIMECLOUD_QUEUE_URL"); v != "" {
		cfg.QueueURL = v
	} else if v := os.Getenv("PRIMECLOUD_AGENT_QUEUE_URL"); v != "" {
		cfg.QueueURL = v
	} else if v := os.Getenv("VALKEY_URL"); v != "" {
		cfg.QueueURL = v
	} else if v := os.Getenv("REDIS_URL"); v != "" {
		cfg.QueueURL = v
	}
	if v := os.Getenv("VAULT_ADDR"); v != "" {
		cfg.VaultAddr = strings.TrimSpace(v)
	} else if v := os.Getenv("PRIMECLOUD_AGENT_VAULT_ADDR"); v != "" {
		cfg.VaultAddr = strings.TrimSpace(v)
	}

	// 2a. Vault AppRole Credentials (preferred machine authentication)
	if v := os.Getenv("PRIMECLOUD_AGENT_VAULT_ROLE_ID"); v != "" {
		cfg.VaultRoleID = strings.TrimSpace(v)
	} else if v := os.Getenv("VAULT_ROLE_ID"); v != "" {
		cfg.VaultRoleID = strings.TrimSpace(v)
	} else if idBytes, err := os.ReadFile("/etc/primecloud/credentials/vault_role_id"); err == nil {
		cfg.VaultRoleID = strings.TrimSpace(string(idBytes))
	}

	if v := os.Getenv("PRIMECLOUD_AGENT_VAULT_SECRET_ID"); v != "" {
		cfg.VaultSecretID = strings.TrimSpace(v)
	} else if v := os.Getenv("VAULT_SECRET_ID"); v != "" {
		cfg.VaultSecretID = strings.TrimSpace(v)
	} else if secBytes, err := os.ReadFile("/etc/primecloud/credentials/vault_secret_id"); err == nil {
		cfg.VaultSecretID = strings.TrimSpace(string(secBytes))
	}

	// Support dedicated AppRole JSON file (/etc/primecloud/credentials/vault_approle.json)
	if cfg.VaultRoleID == "" || cfg.VaultSecretID == "" {
		if appRoleData, err := os.ReadFile("/etc/primecloud/credentials/vault_approle.json"); err == nil {
			var ar struct {
				RoleID   string `json:"role_id"`
				SecretID string `json:"secret_id"`
			}
			if err := json.Unmarshal(appRoleData, &ar); err == nil {
				if cfg.VaultRoleID == "" {
					cfg.VaultRoleID = strings.TrimSpace(ar.RoleID)
				}
				if cfg.VaultSecretID == "" {
					cfg.VaultSecretID = strings.TrimSpace(ar.SecretID)
				}
			}
		}
	}

	// 2b. Vault Token Fallback (direct scoped token)
	if v := os.Getenv("PRIMECLOUD_AGENT_VAULT_TOKEN"); v != "" {
		cfg.BootstrapToken = strings.TrimSpace(v)
	} else if v := os.Getenv("PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN"); v != "" {
		cfg.BootstrapToken = strings.TrimSpace(v)
	} else if v := os.Getenv("VAULT_TOKEN"); v != "" {
		cfg.BootstrapToken = strings.TrimSpace(v)
	} else if tokBytes, err := os.ReadFile("/etc/primecloud/credentials/vault_token"); err == nil {
		cfg.BootstrapToken = strings.TrimSpace(string(tokBytes))
	} else if tokBytes, err := os.ReadFile("/etc/primecloud/vault-token"); err == nil {
		cfg.BootstrapToken = strings.TrimSpace(string(tokBytes))
	} else if tokBytes, err := os.ReadFile("/etc/primecloud/bootstrap-token"); err == nil {
		cfg.BootstrapToken = strings.TrimSpace(string(tokBytes))
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_CERT_DIR"); v != "" {
		cfg.CertDir = v
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_RESOURCE_DIR"); v != "" {
		cfg.ResourceDir = v
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_DOCKER_HOST"); v != "" {
		cfg.DockerHost = v
	} else if v := os.Getenv("DOCKER_HOST"); v != "" {
		cfg.DockerHost = v
	}

	if v := os.Getenv("PRIMECLOUD_AGENT_HEARTBEAT_INTERVAL_SEC"); v != "" {
		if sec, err := strconv.Atoi(v); err == nil && sec > 0 {
			cfg.HeartbeatInterval = time.Duration(sec) * time.Second
		}
	}

	if v := os.Getenv("PRIMECLOUD_AGENT_LOG_LEVEL"); v != "" {
		switch strings.ToUpper(v) {
		case "DEBUG":
			cfg.LogLevel = slog.LevelDebug
		case "INFO":
			cfg.LogLevel = slog.LevelInfo
		case "WARN":
			cfg.LogLevel = slog.LevelWarn
		case "ERROR":
			cfg.LogLevel = slog.LevelError
		}
	}

	// Validate critical parameters
	if cfg.ControlPlaneURL == "" {
		return nil, fmt.Errorf("%w: ControlPlaneURL must not be empty", ErrInvalidConfig)
	}
	if cfg.VaultAddr == "" {
		return nil, fmt.Errorf("%w: VaultAddr must not be empty", ErrInvalidConfig)
	}

	return cfg, nil
}
