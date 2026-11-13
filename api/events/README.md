# Event contracts

Event payloads are defined as Protobuf messages under [`api/proto`](../proto) and
versioned by package (`parallelf.<domain>.v1`). `buf lint` and `buf breaking`
run in CI, so a change that would break an existing consumer fails the build.

## Envelope

Events use the CloudEvents 1.0 attribute set. The payload is the Protobuf
message encoded as protojson (`content-type: application/json`).

| Attribute | Example | Notes |
|---|---|---|
| `ce-specversion` | `1.0` | |
| `ce-id` | `0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f` | UUIDv7, also the deduplication key |
| `ce-source` | `/parallelf/core/pf-core` | Producing service |
| `ce-type` | `parallelf.core.v1.ProjectCreated` | Fully qualified message name |
| `ce-time` | `2026-11-13T18:21:00Z` | RFC 3339, UTC |
| `ce-subject` | `project/0193a7c2-...` | Entity the event is about |
| `ce-pfschemaversion` | `1` | Incremented on additive payload changes |
| `content-type` | `application/json` | protojson |

## Catalogue (v1)

| Type | Subject | Producer | Status |
|---|---|---|---|
| `parallelf.core.v1.ProjectCreated` | `pf.core.evt.project.created` | pf-core | Written to the outbox |
| `parallelf.core.v1.ProjectDeleted` | `pf.core.evt.project.deleted` | pf-core | Written to the outbox |

## Delivery

Producers write the event to their schema's `outbox` table in the same
database transaction as the state change (transactional outbox). In this
phase events stop there: the relay that publishes outbox rows to NATS
JetStream arrives with the event backbone milestone. Until then the outbox is
an append-only record that tests assert on.

## Compatibility rules

1. Never reuse or renumber a field. Removed fields are marked `reserved`.
2. New fields are optional and consumers ignore unknown fields.
3. A change in meaning needs a new message or a new package version (`v2`).
