# Architecture Decision Records

Format: [MADR](https://adr.github.io/madr/)-style, short. One decision per file. Status values: Proposed · Accepted · Superseded by ADR-XXXX.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-decisions-local-first.md) | Record decisions; local-first, cost-conscious platform | Accepted |
| [0002](0002-nats-jetstream.md) | NATS JetStream as the event backbone | Accepted |
| [0003](0003-modular-monolith-per-domain.md) | Modular monolith per bounded context | Accepted |
| [0004](0004-postgres-schema-per-service.md) | One PostgreSQL instance, schema per service | Accepted |
| [0005](0005-custom-go-gateway.md) | Custom Go API gateway | Accepted |
| [0006](0006-level-triggered-reconciliation.md) | Level-triggered reconciliation for agents | Accepted |
| [0007](0007-own-orchestrator-k3s-for-platform.md) | Own workload orchestrator; k3s only for deploying the platform | Accepted |
| [0008](0008-identity-service.md) | Own identity service on standard primitives | Accepted |
| [0009](0009-postgres-first-telemetry.md) | Postgres-first telemetry; OpenSearch optional | Accepted |
| [0010](0010-read-only-ai-with-citation-validation.md) | Read-only AI with deterministic citation validation | Accepted |

Template: copy `0000-template.md`, increment the number, keep it under one page.
