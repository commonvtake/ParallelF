# ADR-0003: Modular monolith per bounded context

- Status: Accepted
- Date: 2026-11-10

## Context
A function-per-service design (scheduler, IPAM, reconciler, alerts, incidents … as separate services) would mean 25+ processes, each with its own runtime overhead, config, certs and health checks, on a 16 GB machine.

## Decision
Each bounded context (core, cloud, vpn, netguard, lab, ai) ships as **one control-plane binary** with strict internal packages (`api`, `scheduler`, `reconciler`, `store`, …). Privileged host work lives in separate small **agents**. A few satellites exist where the language or runtime differs (`pf-ng-detect` in Python, sensors).

## Alternatives considered
- Fine-grained microservices: maximal independence, prohibitive RAM and ops cost here.
- One monolith for everything: simplest, but it erases the domain boundaries and the security isolation between, e.g., identity and AI.

## Consequences
- Positive: ~12 deployables; real boundaries (separate DB roles, NATS identities, APIs); easy to split a module out later.
- Negative: modules within a binary scale together; a crash takes down the whole context (mitigated by restarts and reconciliation).
