# PrimeCloud Agent Operations Guide

**Document ID:** PCA-DOCS-OPERATIONS  
**Phase:** 03 — PrimeCloud Agent (Go)  
**Status:** AUTHORITATIVE OPERATIONAL GUIDE  

---

## 1. Installation & Service Configuration

The Agent is installed as a systemd unit at `/etc/systemd/system/primecloud-agent.service`.

### 1.1 Environment Configuration File (`/etc/primecloud/agent.env`)
```bash
PRIMECLOUD_AGENT_NODE_ID="node-compute-us-east-1"
PRIMECLOUD_AGENT_CONTROL_PLANE_URL="cp.primecloud.internal:50051"
PRIMECLOUD_AGENT_VAULT_ADDR="https://vault.primecloud.internal:8200"
PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN="/etc/primecloud/bootstrap.token"
PRIMECLOUD_AGENT_CERT_DIR="/etc/primecloud/certs"
PRIMECLOUD_AGENT_HEARTBEAT_INTERVAL_SEC=10
PRIMECLOUD_AGENT_RECONCILE_INTERVAL_SEC=30
PRIMECLOUD_AGENT_LOG_LEVEL="info"
```

### 1.2 Systemd Unit Lifecycle
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable on boot and start immediately
sudo systemctl enable --now primecloud-agent

# Check service status
sudo systemctl status primecloud-agent

# Inspect structured logs
sudo journalctl -u primecloud-agent -f -o json
```

---

## 2. Operation Dispatching & Management

All mutations on compute nodes occur via strongly-typed Operation Envelopes dispatched by the Control Plane over gRPC.

### 2.1 Supported Operation Types
| Operation Type | Target | Description |
|:---|:---|:---|
| `deploy_workload` | Container | Creates & starts hardened application container |
| `restart_workload` | Container | Graceful stop (5s timeout) followed by boot |
| `remove_workload` | Container | Stops and purges container instance |
| `provision_postgres` | PostgreSQL | Creates volume, stores creds in Vault, boots PG container |
| `backup_postgres` | PostgreSQL | Executes dump and stores encrypted artifact |
| `restore_postgres` | PostgreSQL | Restores dump from encrypted backup artifact |
| `provision_valkey` | Valkey | Allocates volume, sets Vault auth token, boots Valkey |
| `backup_valkey` | Valkey | Generates RDB snapshot and packages backup |
| `restore_valkey` | Valkey | Validates and restores RDB snapshot |
| `configure_route` | Caddy | Validates and reloads ingress reverse-proxy route |
| `remove_route` | Caddy | Purges route snippet and reloads Caddy |

---

## 3. Node Drain & Maintenance

When performing host maintenance (kernel updates, hardware replacement, re-provisioning):
1. Control Plane sends `drain_node = true` in Heartbeat response or Admin command.
2. The Agent sets internal state to `DEGRADED` and disables admission control (`CanAcceptOperations` returns `false`).
3. Running containers remain untouched until Control Plane migrates traffic and schedules removals.
4. Once container count reaches 0, systemd service can be safely stopped:
   ```bash
   sudo systemctl stop primecloud-agent
   ```