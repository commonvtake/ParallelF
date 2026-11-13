# ADR-0012: One Go module and Make for Phase 1

- Status: Accepted
- Date: 2026-11-13

## Context
[04-monorepo-structure](../architecture/04-monorepo-structure.md) planned one Go module per service joined by `go.work`, a `Taskfile.yml` runner, `sqlc` for queries and OpenAPI code generation for Go handlers. At the foundation stage there are two small Go services sharing most of their code.

## Decision
- Use a **single Go module** at the repository root (`github.com/commonvtake/parallelf`). Service code stays under `services/<name>/internal`, so the compiler still prevents one service from importing another's internals.
- Use **GNU Make** as the task runner. It is already present on every development machine and CI runner.
- Write pf-core's few SQL statements by hand with `pgx`, and its handlers against `net/http`. The OpenAPI contract is enforced from the outside: the integration tests validate live responses against it, and the dashboard's types are generated from it.

## Alternatives considered
- Multi-module workspace now: more files and release mechanics with no benefit until services need independent dependency sets.
- Taskfile: nicer syntax, one more tool to install.

## Consequences
- Positive: one `go.mod`, one lint and test invocation, simpler Docker builds.
- Negative: all Go services share dependency versions. Split into modules when that becomes a constraint.
- Revisit `sqlc` and server code generation when a service has enough queries or endpoints for hand-written code to become the larger risk.
