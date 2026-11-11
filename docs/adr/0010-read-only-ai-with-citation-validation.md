# ADR-0010: Read-only AI with deterministic citation validation

- Status: Accepted
- Date: 2026-11-10

## Context
The AI assistant analyzes telemetry that attackers can influence (prompt injection), and its conclusions could mislead an incident responder. It also sends data to a third-party API.

## Decision
- The assistant gets **only read-only, parameterized, bounded tools**, through a service account with `*.read` permissions; its DB role can write only its own schema.
- Reports are submitted through a schema-enforced `submit_report` tool. A **deterministic validator** checks that every claim cites evidence IDs returned during the investigation and that the cited evidence contains the claimed entities and times.
- Reports are labelled AI-generated and attach to incidents only after explicit, audited human approval. Recommended actions are links, never automatic calls.
- Data minimization and budgets are enforced in the tool layer and orchestrator.

## Alternatives considered
- Agent with action tools (revoke device, quarantine workload): impressive demos; unacceptable blast radius under prompt injection.
- LLM-as-judge for validation: cheaper to build; not deterministic or auditable.

## Consequences
- Positive: worst-case outcome of manipulation is a flagged, unapproved report; measurable quality (citation pass rate).
- Negative: some correct but weakly cited insights get `needs_review`; more engineering in the tool layer.
