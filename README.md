# primecloud-agent

The privileged node agent running on compute hosts, executing typed infrastructure and runtime operations commanded by the Control Plane over gRPC/mTLS.

## PrimeCloud Context

This repository is part of PrimeCloud.

- **Architecture Baseline:** PrimeCloud Architecture Baseline v1.0
- **Roadmap:** Master Roadmap v2 (PCA-MASTER-ROADMAP-002)
- **Implementation phase(s):** Phase 03 (PrimeCloud Agent)

## Status

This is a **Phase 00 skeleton**.

- No implementation code is present.
- No GitHub remote is configured.
- GitHub repository creation and push are **DEFERRED**.

## Purpose

When implemented, this repository will contain the Go-based privileged daemon running on compute nodes, receiving typed commands from the Control Plane via gRPC over mTLS, managing Docker workloads, reverse proxy configurations, and node metrics.

## Governance

- See `CONTRIBUTING.md` (Phase 00, Module AG-00-03).
- See `SECURITY.md` (Phase 00, Module AG-00-17).
- See `LICENSE` (placeholder).
