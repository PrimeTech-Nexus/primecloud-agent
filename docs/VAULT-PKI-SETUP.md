# HashiCorp Vault PKI Setup for PrimeCloud Agent

**Document ID:** PCA-DOCS-VAULT-PKI-SETUP  
**Phase:** 03 — PrimeCloud Agent (Go)  
**Status:** AUTHORITATIVE OPERATIONAL GUIDE  

---

## 1. Overview

PrimeCloud Agent nodes establish outbound mTLS gRPC connections to the Control Plane. Mutual TLS requires an authoritative internal Public Key Infrastructure (PKI). This infrastructure is backed by HashiCorp Vault's PKI secrets engine using a two-tier hierarchy:
1. **Root CA (`pki`):** Self-signed root authority (`primecloud.internal`) with long TTL (e.g. 10 years).
2. **Intermediate CA (`pki_int`):** Subordinate authority (`primecloud.internal Intermediate Authority`) signed by Root CA, with medium TTL (e.g. 5 years).
3. **Agent Role (`pki_int/roles/agent`):** Role issuing short-lived client/server certificates for compute nodes (`ttl=24h`, `max_ttl=720h`).

---

## 2. Step-by-Step PKI Initialization

### 2.1 Enable and Configure Root CA
```bash
# Enable root PKI engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki

# Generate Root CA
vault write pki/root/generate/internal \
    common_name="primecloud.internal" \
    ttl=87600h

# Configure Root CA issuing URLs
vault write pki/config/urls \
    issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
    crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
```

### 2.2 Enable and Configure Intermediate CA
```bash
# Enable intermediate PKI engine
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

# Generate CSR for Intermediate CA
CSR=$(vault write -format=json pki_int/intermediate/generate/internal \
    common_name="primecloud.internal Intermediate Authority" \
    ttl=43800h | jq -r '.data.csr')

# Sign Intermediate CSR with Root CA
CERT=$(vault write -format=json pki/root/sign-intermediate \
    csr="$CSR" \
    format=pem_bundle \
    ttl=43800h | jq -r '.data.certificate')

# Import Signed Certificate into Intermediate Engine
vault write pki_int/intermediate/set-signed certificate="$CERT"
```

### 2.3 Configure Agent PKI Role
```bash
vault write pki_int/roles/agent \
    allowed_domains="primecloud.internal,agent.primecloud.internal,localhost,127.0.0.1" \
    allow_subdomains=true \
    allow_bare_domains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    max_ttl=720h \
    ttl=24h
```

---

## 3. Node Bootstrap Workflow

1. Node is provisioned with a one-time bootstrap token (`PRIMECLOUD_AGENT_BOOTSTRAP_TOKEN` or `/etc/primecloud/bootstrap-token`).
2. Agent boots, connects to Vault via `internal/vault/client.go`.
3. Agent invokes `BootstrapNode()` requesting initial certificate from `pki_int/issue/agent`.
4. Stored at `/etc/primecloud/agent/` with:
   - `agent.key`: `0600` permissions (readable only by agent process).
   - `agent.crt`: `0644` permissions.
   - `ca.crt`: `0644` permissions.
5. Automatic certificate rotation triggers at 50% TTL.
