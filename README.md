# primecloud-agent

The privileged node agent running on compute hosts, executing typed infrastructure operations commanded by the Control Plane.

## PrimeCloud

PrimeCloud is a cloud platform for applications and businesses.

> You build the application. PrimeCloud handles the complexity behind it.

- **Architecture Baseline:** PrimeCloud Architecture Baseline v1.0
- **Roadmap:** Master Roadmap v2
- **Implementation phase(s):** Phase 03 (PrimeCloud Agent)
- **Repository status:** Phase 00 — Architecture & Engineering Foundation

## Repository Purpose

When implemented, this repository will contain the Go-based privileged daemon running on PrimeCloud compute nodes. It receives typed commands from the Control Plane via gRPC over mTLS and executes them strictly within host boundaries.

In PrimeCloud's three-tier trust model, the Agent holds the PRIVILEGED role, translating orchestration decisions from the HIGH TRUST Control Plane into concrete runtime actions on compute nodes while keeping LOW TRUST customer workloads isolated.

The Agent manages Docker container lifecycles, dynamic reverse proxy configurations (Caddy), localized state (Postgres and Valkey customer containers), real-time log streaming, system metrics collection, and node self-healing.

## Repository Scope

- Privileged Agent daemon binary (`cmd/agent`)
- Secure transport layer (gRPC over TLS with Vault PKI mTLS)
- Typed operations protocol implementation
- Docker container runtime manager and application lifecycle drivers
- Managed service drivers (PostgreSQL, Valkey, Caddy reverse proxy)
- Interactive terminal session handler and log forwarder
- Node resource metrics collector and reconciliation loops
- Local backup, recovery, and host security primitives

## Repository Non-Goals

- No Control Plane orchestration, policy decision-making, or database authority
- No customer-facing frontend or web dashboard code
- No developer CLI implementations
- No container image building or image synthesis workloads
- Never grants host root, Docker socket, or Control Plane credentials to customer workloads

## Relationship to Other Repositories

- Connects outbound to `primecloud-control-plane` over gRPC with mTLS
- Executes containerized application workloads using images pulled from GHCR (produced by `primecloud-build`)
- Reports telemetry, node status, and operation logs back to `primecloud-control-plane`

## Development Status

This repository is in **Phase 00**.

- No implementation code is present.
- No GitHub remote is configured.
- GitHub repository creation and push are **DEFERRED**.

## Governance

- See `CONTRIBUTING.md` for contribution rules.
- See `CODE_OF_CONDUCT.md` for conduct policy.
- See `SECURITY.md` for security policy.
- See `LICENSE` for licensing (placeholder — decision pending).

## Notes

- Do not introduce implementation code.
- Do not commit secrets, credentials, or customer data.
- Any architecture change requires an ADR and Founder approval.
