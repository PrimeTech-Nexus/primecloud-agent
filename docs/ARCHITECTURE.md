# PrimeCloud Agent Architecture

**Document ID:** PCA-DOCS-ARCHITECTURE  
**Phase:** 03 — PrimeCloud Agent (Go)  
**Status:** AUTHORITATIVE ARCHITECTURE SPECIFICATION  

---

## 1. System Overview

The PrimeCloud Agent is a single statically linked daemon written in Go running as a systemd service on every compute node. The Agent acts under the fundamental architectural invariant:

> **"The Control Plane decides; the Agent executes."**

The Agent does not contain autonomous business logic or unprompted scheduling; it connects outbound via mutual TLS (mTLS) over gRPC to the PrimeCloud Control Plane, registers node hardware and kernel metadata, opens a bidirectional streaming channel for receiving typed operations, reports real-time telemetry/heartbeats, executes declarative state reconciliation, and participates in encrypted backup/restore workflows.

```
       +-------------------------------------------------------------+
       |                  Control Plane (FastAPI)                    |
       +-------------------------------------------------------------+
             ^                                           |
    mTLS gRPC| (Outbound Handshake)         Operation RPC| (Typed Envelopes)
             |                                           v
       +-------------------------------------------------------------+
       |                     PrimeCloud Agent                        |
       |  +-------------------------------------------------------+  |
       |  | Dispatcher & Registry (Idempotency & Resource Locks)  |  |
       |  +-------------------------------------------------------+  |
       |  | Telemetry & Heartbeat | State Reconciler & Drift      |  |
       |  +-----------------------+-------------------------------+  |
       |  | Ingress (Caddy)       | Datastores (Postgres, Valkey) |  |
       |  +-----------------------+-------------------------------+  |
       |  | Docker Engine Runtime (Hardened Multi-Tenant Profile) |  |
       |  +-------------------------------------------------------+  |
       +-------------------------------------------------------------+
             |                     |                     |
             v                     v                     v
     [Customer Apps]       [PostgreSQL DB]        [Valkey Cache]
```

---

## 2. Core Subsystems

### 2.1 Identity, Vault & PKI (`internal/vault`, `internal/identity`)
- Bootstraps identity using a single-use bootstrap token resolved from memory or file.
- Issues short-lived x509 certificates from Vault Intermediate CA (`pki_int/roles/agent`).
- Persists certificate bundles with atomic file writes (`cert.pem`, `key.pem`, `ca.pem`) with strict `0600` permissions.
- Rotates certificates automatically in the background at 70% TTL with seamless connection overlap.

### 2.2 gRPC Transport & Protocol (`internal/transport`, `internal/protocol`)
- Outbound-only connectivity to prevent inbound port exposure on compute nodes.
- mTLS with mutual validation and SNI checking.
- Exponential backoff reconnection loop with jitter.

### 2.3 Operations Engine (`internal/operations`)
- Thread-safe registry mapping typed operations (e.g. `deploy_workload`, `provision_postgres`) to handler functions.
- Schema validation enforcing strict JSON structure before dispatch.
- In-memory idempotency tracking returning cached responses for retransmitted operation IDs.
- Granular per-resource mutex locks ensuring sequential mutations on shared state.

### 2.4 Hardened Container Runtime (`internal/runtime`)
- Direct interaction with Docker engine via local engine socket.
- Enforces strict multi-tenant isolation envelope:
  - Drop all capabilities (`DROP: ALL`), allowlist only `NET_BIND_SERVICE`.
  - Non-root user execution (`1000:1000` / `999:999`).
  - `no-new-privileges:true`.
  - Strict prohibition against mounting `/var/run/docker.sock`.
  - Strict prohibition against `Privileged: true`.
  - Cgroups v2 memory, CPU, and PID limits.

### 2.5 Managed State Drivers
- **PostgreSQL (`internal/postgres`):** Volume allocation, credential generation into Vault KV (`primecloud/resources/postgres/<id>`), container provisioning, dump backup, restore, and lifecycle management.
- **Valkey (`internal/valkey`):** Memory configuration, auth token generation into Vault KV (`primecloud/resources/valkey/<id>`), RDB snapshots, restore, and lifecycle management.
- **Caddy Ingress (`internal/caddy`):** Reverse proxy configuration snippets, atomic syntax validation, site activation, and zero-downtime dynamic reload via Caddy admin API (`127.0.0.1:2019/load`).

### 2.6 Telemetry & Heartbeat (`internal/telemetry`)
- Periodic heartbeat delivery with CPU/Memory/Disk utilization metrics.
- Asynchronous event reporting (`INFO`, `WARN`, `ERROR`, `CRITICAL`).
- Container inventory reporting for full host transparency.
- Dynamic control-plane directive handling (`rotate_certificate`, `trigger_reconciliation`, `drain_node`).

### 2.7 State Reconciliation (`internal/state`, `internal/reconciliation`)
- Collects live host state from container runtime.
- Evaluates against Control Plane desired state.
- Classifies drift: `MISSING`, `STATE_MISMATCH`, `IMAGE_MISMATCH`, `EXTRANEOUS`.
- Plans and applies authorized repairs (restarting stopped containers, provisioning missing workloads, pruning unauthorized containers).

### 2.8 Backup & Recovery (`internal/backup`, `internal/recovery`)
- AES-256-GCM authenticated encryption for database dumps and volume snapshots.
- Cryptographic SHA-256 integrity verification.
- Signed JSON manifests (`<backup_id>.manifest.json`).
- Automated decryption and post-restoration format verification before bringing services online.

### 2.9 Node Failure & Graceful Degradation (`internal/agent`)
- Continuous diagnostics checking Docker runtime and Vault reachability.
- Tri-state health assessment: `HEALTHY`, `DEGRADED`, `UNHEALTHY`.
- Graceful drain mode rejecting new workload placement while preserving running customer workloads.