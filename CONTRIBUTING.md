# Contributing to primecloud-agent

Thank you for your interest in PrimeCloud.

This document defines contribution rules for this repository during
Phase 00 — Architecture & Engineering Foundation.

## Current Phase

This repository is in **Phase 00**.

- No implementation code is present.
- No GitHub remote is configured.
- Contributions are not yet open externally.
- All work follows the Phase 00 governance model.

## Governance Model

PrimeCloud follows a Founder-authorized governance model:

- **Founder:** Final architectural authority.
- **Principal Architect / Governance Authority:** Plans, tasks, reviews.
- **Implementation Engineer:** Implements approved tasks only.

Any architectural change requires an **Architecture Change Proposal (ACP)**
and explicit Founder approval.

## Branching

- `main` is protected.
- Feature work uses `feature/<module>`.
- Fixes use `fix/<issue>`.
- Urgent fixes use `hotfix/<issue>`.
- Non-functional work uses `chore/<task>`.
- Documentation uses `docs/<topic>`.

See the workspace-level `BRANCHING.md` for details.

## Commit Style

Commits are focused and scoped. Each commit message identifies:

- The module or task (e.g., `ag-00-03`)
- The category (e.g., `docs`, `chore`, `feat`, `fix`)
- A concise description

Unrelated changes are prohibited in a single commit.

## Testing Requirements

When implementation begins (Phase 01+), every contribution must
include tests appropriate to the change. Tests are defined per module
by the approved implementation specification.

## Security

- Do not commit secrets, credentials, or customer data.
- See `SECURITY.md` for the security policy.
- Report security concerns through the process described in `SECURITY.md`.

## Code of Conduct

See `CODE_OF_CONDUCT.md`.

## Questions

Direct questions to the Principal Architect for this project.
