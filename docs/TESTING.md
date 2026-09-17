# PrimeCloud Agent Testing & Verification Guide

**Document ID:** PCA-DOCS-TESTING  
**Phase:** 03 — PrimeCloud Agent (Go)  
**Status:** AUTHORITATIVE TESTING SPECIFICATION  

---

## 1. Test Architecture

The PrimeCloud Agent test suite is organized into three distinct verification tiers:

1. **Unit & Module Smoke Tests (`tests/smoke/<module>/`):**
   - Individual module verification (AG-00 through AG-14).
   - Verifies isolated behavior, schema validation, idempotency, drivers, metrics, and error boundaries.
2. **Chunk Integration Tests (`tests/integration/`):**
   - `chunk_a_test.go`: AG-00 to AG-03 end-to-end (Vault bootstrap, mTLS, registration, reconnect, rotation).
   - `chunk_b_test.go`: AG-04 to AG-14 end-to-end (Dispatcher, Docker runtime, Postgres, Valkey, Caddy, Telemetry, Reconciliation, Backup, Recovery, Node failure).
3. **Full Lifecycle Integration Test (`tests/integration/agent_lifecycle_test.go`):**
   - Complete 13-step lifecycle verification executing the entire Agent surface area against real Vault Dev mode and mock Control Plane server.

---

## 2. Running Tests

### 2.1 Complete Test Suite
```bash
go test -v ./...
```

### 2.2 Running Integration Tests Only
```bash
go test -v ./tests/integration/...
```

### 2.3 Running Specific Module Smoke Tests
```bash
go test -v ./tests/smoke/operations/...
go test -v ./tests/smoke/postgres/...
go test -v ./tests/smoke/valkey/...
go test -v ./tests/smoke/caddy/...
```

### 2.4 Code Formatting and Static Analysis
```bash
gofmt -l .
go vet ./...
```

---

## 3. Real Vault Dev Harness (`tests/testenv/vault.go`)

Tests require a running HashiCorp Vault instance. The test suite provides `testenv.EnsureVaultDev(t)`, which:
1. Detects whether Vault is running on `127.0.0.1:8200`.
2. If absent, launches `vault server -dev -dev-listen-address=127.0.0.1:8200 -dev-root-token-id=root`.
3. Ensures Root CA (`pki`), Intermediate CA (`pki_int`), role `agent`, and KV engine (`primecloud`) are mounted and ready.