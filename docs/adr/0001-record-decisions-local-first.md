# ADR-0001: Record decisions; local-first, cost-conscious platform

- Status: Accepted
- Date: 2026-11-10

## Context
ParallelF is a solo portfolio project on a 16 GB Windows 11 workstation. Reviewers value seeing *why* choices were made. Cloud spend must stay near zero.

## Decision
1. Record significant decisions as ADRs in `docs/adr/`.
2. Everything must run locally first (WSL2 + Docker Compose, optionally a Hyper-V VM with k3s). Cloud (AWS) is an optional, ephemeral demo target created and destroyed with Terraform.

## Alternatives considered
- Cloud-first on managed services (EKS, RDS, MSK): realistic, but costs money continuously and hides the infrastructure work.
- No ADRs: faster, but loses the reasoning that makes the project resume-worthy.

## Consequences
- Positive: zero idle cost; full control over networking and virtualization; visible engineering judgment.
- Negative: hardware limits (RAM) shape the design (see ADR-0003, ADR-0009); no managed HA.
