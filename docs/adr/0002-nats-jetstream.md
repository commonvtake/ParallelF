# ADR-0002: NATS JetStream as the event backbone

- Status: Accepted
- Date: 2026-11-10

## Context
The platform needs durable domain events, high-volume telemetry with backpressure, request/reply between control planes and agents, short-TTL key-value data (heartbeats), and per-identity authorization, all within a small RAM budget.

## Decision
Use NATS with JetStream for streams, consumers and KV, plus core NATS request/reply for agent pokes and desired-state fetches. Identities are NKey users with explicit subject permissions. Streams, consumers and KV buckets are provisioned as code.

## Alternatives considered
- Kafka / Redpanda: excellent for very high throughput, but heavier, and no built-in request/reply or KV with TTL.
- RabbitMQ: mature queues; streams and KV less integrated; more RAM.
- Redis Streams: light, but weaker auth model and durability story for this use.

## Consequences
- Positive: one ~20 MB binary covers events, telemetry, RPC and KV; subject-level ACLs map neatly to the trust model.
- Negative: smaller ecosystem than Kafka (fewer connectors); consumer semantics must be learned carefully (ack, redelivery, dedupe window).
- Follow-ups: outbox + idempotent consumers (M1) to get exactly-once *effects*.
