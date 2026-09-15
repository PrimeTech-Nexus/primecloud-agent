# Security Policy

## Purpose

This document defines the security policy for this repository during
Phase 00 — Architecture & Engineering Foundation.

PrimeCloud treats security as a foundational architectural requirement,
not a feature. Security is embedded in every phase of the platform.

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in
PrimeCloud, do not open a public issue.

Report security concerns through the process described at the
project's security documentation. Do not disclose the issue publicly
until it has been reviewed and addressed.

## Scope

This repository is currently in **Phase 00**.

- No implementation code is present.
- No production system is running.
- No customer data is present.

The security policy below applies as the platform is implemented
and will be refined in future modules.

## Security Principles

PrimeCloud follows these principles:

1. **Three-tier trust model.**
   - Customer workload = LOW TRUST
   - PrimeCloud Agent = PRIVILEGED
   - Control Plane = HIGH TRUST

2. **The Control Plane decides. The Agent executes.**

3. **Customer workloads must never receive:**
   - Host root
   - Docker socket
   - Unrestricted host shell
   - Control Plane database credentials
   - Master Control Plane credentials
   - GitHub App private key
   - Cloudflare master credentials
   - Payment secrets
   - Vault administrative credentials
   - mTLS CA/signing material

4. **No secrets in Git.**

5. **No secrets in logs.**

6. **No secrets baked into container images.**

7. **Secrets are managed through Vault.**

8. **Every privileged action is auditable.**

9. **Tenant isolation is enforced everywhere.**

10. **Any architecture change requires an ACP and Founder approval.**

## Do Not Commit

Do not commit:

- Secrets
- API keys
- Passwords
- Tokens
- Private keys
- `.env` files
- Customer data
- Credentials of any kind

## Accepted Architecture

PrimeCloud V1 uses:

- Docker runtime
- Go Agent with gRPC over TLS and Vault PKI
- FastAPI Control Plane with PostgreSQL and Valkey
- Rootless BuildKit and Kaniko for builds
- GHCR for container images
- HashiCorp Vault for secrets
- Cloudflare and Caddy for edge
- Cloudflare R2 for object storage
- Paystack for payments

PrimeCloud V1 does **not** use:

- Kubernetes
- AWS / Azure / GCP foundation
- Serverless foundation
- Service mesh
- Microservices redesign
- Terraform as mandatory foundation
- Multi-region compute
- Self-hosted container registry
- RabbitMQ
- VictoriaMetrics
- Secondary payment provider
- Permanent free tier
- Vertical-first scaling

## Reporting

Report security concerns through the process defined by the project
maintainers. Do not disclose publicly.
