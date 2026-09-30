// Package agent provides core lifecycle, configuration, and orchestration for the PrimeCloud Agent daemon.
package agent

import (
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
	ControlPlaneURL     string        `json:"control_plane_url"`
	QueueURL            string        `json:"queue_url"`
	VaultAddr           string        `json:"vault_addr"`
	BootstrapToken      string        `json:"-"` // Never serialized in JSON
	CertDir             string        `json:"cert_dir"`
	ResourceDir         string        `json:"resource_dir"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`
	LogLevel            slog.Level    `json:"log_level"`
	DockerHost          string        `json:"docker_host"`
	ReconcileInterval   time.Duration `json:"reconcile_interval"`
	RotationCheckPeriod time.Duration `json:"rotation_check_period"`
}

// String implements fmt.Stringer to ensure secrets are never leaked in string formatting.
func (c *Config) String() string {
	return fmt.Sprintf("Config{NodeID:%s, AgentID:%s, ControlPlaneURL:%s, QueueURL:%s, VaultAddr:%s, CertDir:%s, ResourceDir:%s, HeartbeatInterval:%v, LogLevel:%v, DockerHost:%s}",
		c.NodeID, c.AgentID, c.ControlPlaneURL, c.QueueURL, c.VaultAddr, c.CertDir, c.ResourceDir, c.HeartbeatInterval, c.LogLevel, c.DockerHost)
}

// DefaultConfig returns baseline configuration defaults.
func DefaultConfig() *Config {
	return &Config{
		ConfigFile:          "/etc/primecloud/agent.yaml",
		NodeID:              "0191c001-0000-7000-8000-000000000001",
		AgentID:             "agent-node-0191c001-0000-7000-8000-000000000001",
		ControlPlaneURL:     "127.0.0.1:50051",
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
	if v := os.Getenv("PRIMECLOUD_AGENT_CONTROL_PLANE_URL"); v != "" {
		cfg.ControlPlaneURL = v
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
		cfg.VaultAddr = v
	} else if v := os.Getenv("PRIMECLOUD_AGENT_VAULT_ADDR"); v != "" {
		cfg.VaultAddr = v
	}
	if v := os.Getenv("PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN"); v != "" {
		cfg.BootstrapToken = v
	} else if v := os.Getenv("VAULT_TOKEN"); v != "" {
		cfg.BootstrapToken = v
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
