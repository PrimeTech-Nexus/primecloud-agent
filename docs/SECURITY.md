# PrimeCloud Agent Security Architecture

**Document ID:** PCA-DOCS-SECURITY  
**Phase:** 03 — PrimeCloud Agent (Go)  
**Status:** AUTHORITATIVE SECURITY SPECIFICATION  

---

## 1. Zero Trust Identity & mTLS Boundary

1. **Outbound-Only Ingress:** Compute nodes do not open listening ports to the public internet for management. The Agent establishes an outbound mTLS gRPC connection to the Control Plane.
2. **Authoritative Vault PKI:**
   - Identity is backed by HashiCorp Vault's intermediate CA (`pki_int`).
   - Certificates carry strict Common Names formatted as `agent-<node-id>.agent.primecloud.internal`.
   - Node bootstrapping consumes a single-use token and generates private keys locally; private keys are never transmitted over the network.
3. **Automated Certificate Rotation:**
   - Certificates are rotated automatically when 70% of TTL has elapsed.
   - An active TLS connection overlap window ensures zero in-flight message loss during rotation.
4. **Revocation Defense:**
   - If a node is decommissioned, the Control Plane rejects mTLS or returns `PermissionDenied` (`AGENT_REVOKED`).
   - The Agent terminates active dispatching and transitions to `STOPPED` immediately.

---

## 2. Hardened Multi-Tenant Container Isolation Profile

All customer containers launched by PrimeCloud Agent run inside a hardened sandbox:

| Control | Implementation | Rationale |
|:---|:---|:---|
| **Capabilities** | `CapDrop: ["ALL"]`, `CapAdd: ["NET_BIND_SERVICE"]` | Strips all kernel capabilities; restricts raw sockets and admin control |
| **Privilege Escalation** | `SecurityOpt: ["no-new-privileges:true"]` | Prevents `setuid` binaries from gaining elevated privileges |
| **User ID** | `User: "1000:1000"` (App) / `"999:999"` (Valkey) | Forbids execution as root (`UID 0`) inside container |
| **Docker Socket** | Explicit error `ErrDockerSocketForbidden` | Strictly rejects any bind mount containing `docker.sock` |
| **Privileged Mode** | Explicit error `ErrPrivilegedNotAllowed` | Disallows `Privileged: true` container runtime flags |
| **Namespaces** | Isolated PID, IPC, UTS, Mount namespaces | Containers cannot inspect host processes or shared memory |
| **Cgroups v2 Limits** | `MemoryBytes`, `NanoCPUs`, `PidsLimit` | Prevents Denial of Service and noisy-neighbor exhaustion |
| **AppArmor** | `SecurityOpt: ["apparmor=docker-default"]` | Restricts access to host hardware and kernel filesystems |

---

## 3. Secret Protection & Zero-Leakage Invariant

1. **Zero Hardcoded Secrets:** All database passwords, tokens, and encryption keys are generated dynamically and stored exclusively in Vault KV (`primecloud/resources/*`).
2. **Log Redaction:** The structured slog handler interceptor automatically strips and replaces tokens, private keys, passwords, and authorization headers with `[REDACTED]`.
3. **Restricted File Permissions:** All certificate stores, tokens, and backup directories on the node are created with `0600` (read/write owner only) or `0700` directories.
4. **AES-256-GCM Backup Encryption:** All backups on the node are encrypted before leaving local storage using 32-byte authenticated keys and signed with SHA-256 integrity manifests.