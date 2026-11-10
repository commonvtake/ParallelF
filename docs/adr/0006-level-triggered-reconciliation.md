# ADR-0006: Level-triggered reconciliation for agents

- Status: Accepted
- Date: 2026-11-10

## Context
Node and gateway agents apply privileged changes (VMs, bridges, nftables, WireGuard peers). Messages can be lost, duplicated or reordered, and agents and control planes restart independently.

## Decision
The control plane stores desired state in PostgreSQL. Agents fetch a **complete desired-state snapshot** (with a revision) via NATS request/reply on startup, on a "poke", and every 30 s; diff it against actual host state; and apply idempotent "ensure" operations. Status flows back over JetStream. Agents never delete resources because the control plane is unreachable, and only touch resources labelled as ParallelF-managed.

## Alternatives considered
- Imperative command queue (create/delete commands): simpler at first; lost or replayed commands corrupt state and require complex recovery.
- gRPC bidirectional streams: workable, but needs inbound connectivity or long-lived connections plus the same reconciliation logic anyway.

## Consequences
- Positive: self-healing after crashes, partitions and manual drift; simple mental model (the Kubernetes controller pattern).
- Negative: snapshot size grows with workloads per node (fine at this scale; delta + revision can be added later); convergence latency bounded by poke/resync interval.
