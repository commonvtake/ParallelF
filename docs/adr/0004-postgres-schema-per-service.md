# ADR-0004: One PostgreSQL instance, schema per service

- Status: Accepted
- Date: 2026-11-10

## Context
Each service must own its data, but running six PostgreSQL instances would waste RAM.

## Decision
Run a single PostgreSQL 17 instance with one schema per service, a dedicated owner role (migrations) and runtime role (DML only) per service, **no cross-schema foreign keys or queries**, and a transactional outbox table in each schema. The only documented exception is `pf-ng-detect`'s read-only access to three NetGuard views.

## Alternatives considered
- Database (or instance) per service: strongest isolation; more RAM and ops.
- Shared schema: simplest; destroys ownership boundaries.

## Consequences
- Positive: low footprint; enforceable ownership through grants; any schema can move to its own database without code changes.
- Negative: shared failure and performance domain; no cross-domain referential integrity (handled by APIs, events and reconciliation).
