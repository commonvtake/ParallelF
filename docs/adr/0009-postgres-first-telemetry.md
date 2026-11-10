# ADR-0009: Postgres-first telemetry; OpenSearch optional

- Status: Accepted
- Date: 2026-11-10

## Context
NetGuard stores flows and protocol metadata. OpenSearch is in the preferred stack, but its JVM heap (~1 GB minimum in practice, plus overhead) is a large share of the RAM budget, and most queries are structured (by IP, port, time, community_id).

## Decision
Store normalized telemetry in PostgreSQL daily-partitioned tables (BRIN on time, btree on IP/port/community_id; COPY batching; partition-drop retention). OpenSearch is an **opt-in** profile (`ng-full`) that receives a dual-write for full-text search and long-range analytics. Detection runs on the stream, not on either store.

## Alternatives considered
- OpenSearch-only: great search; always-on RAM cost; two query languages for the AI tools.
- ClickHouse: excellent for analytics; another heavy system outside the preferred stack.
- TimescaleDB: nice ergonomics; an extension dependency for something native partitioning handles.

## Consequences
- Positive: one store and query language by default; the AI tool layer queries a single API.
- Negative: no full-text search without `ng-full`; Postgres needs careful partition/index hygiene.
