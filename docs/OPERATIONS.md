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

### 1.3 Version Inspection
```bash
# Print agent version and commit SHA, then exit immediately
primecloud-agent --version

# Shorthand version check
primecloud-agent -v
```

### 1.4 Safe Host Binary Updates
The Agent runs as a native Linux binary under systemd (`/usr/local/bin/primecloud-agent`). Updates are performed using `scripts/update-agent.sh`.

#### Prerequisites
- Linux host (`x86_64` / `amd64` or `aarch64` / `arm64`)
- Systemd service `primecloud-agent.service` installed and enabled
- Superuser privileges (`root` or `sudo`)
- Host utilities: `curl`, `tar`, `sha256sum`, `systemctl`, `journalctl`, and `flock`

#### Usage Examples
```bash
# 1. Safe Dry-Run (validates download, checksum, tarball, and --version without modifying host)
sudo ./scripts/update-agent.sh --dry-run v0.4.0 <SHA256_CHECKSUM>

# 2. Production Live Update
sudo ./scripts/update-agent.sh v0.4.0 <SHA256_CHECKSUM>

# 3. Explicit flags with custom health timeout
sudo ./scripts/update-agent.sh --tag v0.4.0 --checksum <SHA256_CHECKSUM> --timeout 45
```

#### Verification and Health Signals
The Agent does not run a dedicated HTTP health endpoint. Instead, the updater relies on a multi-stage verification model:
1. **Pre-Execution Check**: Executes `<extracted_binary> --version` in a restricted temporary directory to confirm executable validity and version string output before staging.
2. **Atomic Swap & Backup**: Copies new binary to `.primecloud-agent.new.<pid>` on the same filesystem, preserves owner/permissions via `--reference`, retains the previous binary at `/usr/local/bin/primecloud-agent.bak`, and executes an atomic `mv`.
3. **Systemd Health Signal**: Restarts `primecloud-agent.service` and polls for up to `TIMEOUT_SECONDS`:
   - `systemctl is-active`: must return `active`
   - `systemctl show -p SubState`: must equal `running`
   - `systemctl show -p MainPID`: must return a positive PID verified alive via process signaling (`kill -0`)
   - Emits recent `journalctl` diagnostic output if health verification fails.

> **Operational Limitation:** Process-level liveness confirms the daemon booted and its runtime subsystems initialized. Remote Control Plane registration and Valkey queue consumption require external connectivity and valid credentials in `/etc/primecloud/agent.env`.

#### Failure & Rollback Behavior
- **Exit Code 0:** Update succeeded and verified active.
- **Exit Code 1:** Update failed (or health check timed out); automated rollback successfully restored `/usr/local/bin/primecloud-agent.bak` and verified service is active.
- **Exit Code 2:** Invalid input arguments, unsupported architecture, or missing prerequisite tools.
- **Exit Code 3:** Lock contention; another update is currently executing (`/run/lock/primecloud-agent-update.lock`).
- **Exit Code 4:** Download failure from GitHub Releases over HTTPS.
- **Exit Code 5:** Cryptographic SHA-256 checksum mismatch (artifact discarded immediately).
- **Exit Code 6:** Malicious archive detected (directory traversal `../`, absolute path, or unexpected files).
- **Exit Code 7:** Extracted binary failed pre-execution check.
- **Exit Code 8:** Critical failure; update failed AND automated rollback failed.

#### Manual Recovery Procedure
If an update encounters critical failure:
```bash
# Check service failure reason
sudo journalctl -u primecloud-agent -n 50 --no-pager

# Restore retained previous binary
sudo mv /usr/local/bin/primecloud-agent.bak /usr/local/bin/primecloud-agent
sudo systemctl restart primecloud-agent
sudo systemctl status primecloud-agent
```

### 1.5 Automated Production Deployment Pipeline
Production deployments are orchestrated via `.github/workflows/deploy.yml`.

#### Workflow Triggers
1. **Automated Release Deployment:** Triggers automatically whenever a new GitHub Release is published (`release: types: [published]`).
2. **Controlled Manual Redeployment (`workflow_dispatch`):**
   - **`tag` (required):** Explicit immutable release tag (e.g. `v0.4.0`).
   - **`dry_run` (optional):** Simulates the entire deployment without host mutations.

#### Required GitHub Secrets & Environment Configuration
The workflow targets the `production` environment with serialized concurrency (`production-deployment-pc-node-001-agent`):

| Secret Name | Purpose | Example / Format |
|:---|:---|:---|
| `PROD_HOST` | Production compute node IP or FQDN | `167.86.73.226` / `pc-node-001` |
| `PROD_SSH_USER` | Dedicated unprivileged SSH user | `deploy` |
| `PROD_SSH_KEY` | Dedicated deployment SSH private key | OpenSSH ED25519 private key |
| `PROD_KNOWN_HOSTS` | Exact trusted host key entry | `167.86.73.226 ssh-ed25519 AAAAC3...` |

#### Least-Privilege Host Architecture
To enforce strict defense-in-depth, SSH login does not grant shell access or direct sudo privileges:
1. `deploy` connects via SSH with strict host-key checking (`StrictHostKeyChecking=yes`).
2. Execution is restricted to the hardened wrapper `/opt/primecloud-bootstrap/agent_deploy_wrapper.sh`.
3. Sudo rights on the host are restricted via `/etc/sudoers.d/99-primecloud-agent-deploy`:
   ```sudoers
   deploy ALL=(root) NOPASSWD: /opt/primecloud-bootstrap/agent_deploy_wrapper.sh v* [0-9a-fA-F]*
   deploy ALL=(root) NOPASSWD: /opt/primecloud-bootstrap/agent_deploy_wrapper.sh --dry-run v* [0-9a-fA-F]*
   ```
4. The wrapper validates arguments (`tag`, `checksum`), verifies root ownership of `/opt/primecloud-bootstrap/update-agent.sh`, and invokes the updater with locked parameters.

#### Service Health vs. Control Plane Registration
- **Service Liveness:** The workflow confirms that `primecloud-agent.service` is `active`, `running`, and has an active PID.
- **Control Plane Registration:** The Agent communicates asynchronously with the Control Plane and Valkey. Process liveness does not guarantee that credentials in `/etc/primecloud/agent.env` or network firewalls allow registration. Verify registration via `sudo journalctl -u primecloud-agent -n 50 -o json` to inspect heartbeat and telemetry acknowledgment.

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