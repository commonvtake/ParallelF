# ParallelF Architecture (v0.1, draft)

ParallelF is a unified, self-hosted platform for **cloud computing**, **private networking**, and **defensive security**, designed to run on one 16 GB workstation and deploy to k3s or AWS on demand.

## Reading order

| # | Document | Answers |
|---|---|---|
| 00 | [Assumptions, scope, principles](00-assumptions-and-scope.md) | What we assume, what's in and out, and open questions |
| 01 | [High-level system architecture](01-system-architecture.md) | Planes, components, interaction styles, environments, SLOs |
| 02 | Subsystem architecture: [Platform Core](subsystems/platform-core.md) · [Cloud](subsystems/cloud.md) · [VPN](subsystems/vpn.md) · [NetGuard](subsystems/netguard.md) · [Security Lab](subsystems/security-lab.md) · [AI](subsystems/ai.md) · [Dashboard](subsystems/dashboard.md) | How each subsystem works internally |
| 03 | [Service communication & data flows](03-communication-and-data-flows.md) | Who talks to whom, how, and the end-to-end flows |
| 04 | [Monorepo structure](04-monorepo-structure.md) | Where code lives and the boundary rules |
| 05 | [Database design](05-database-design.md) | Schemas, key DDL, roles, partitioning, retention |
| 06 | [API & event contracts](06-api-and-event-contracts.md) | REST conventions, endpoint catalogue, event envelope, subjects, streams |
| 07 | [Trust boundaries & threat model](07-trust-boundaries-and-threat-model.md) | STRIDE, mitigations with verification tests, NATS ACLs |
| 08 | [Infrastructure requirements](08-infrastructure.md) | Host layout, RAM budget, profiles, PKI, environments, CI/CD, DR |
| 09 | [Subsystem dependencies](09-subsystem-dependencies.md) | Hard/soft dependencies, failure behaviour, startup order |
| 10 | [Roadmap & acceptance criteria](10-roadmap-and-acceptance-criteria.md) | Milestones M0–M16 with testable exit criteria |
| 11 | [Risks & tradeoffs](11-risks-and-tradeoffs.md) | Risk register and decision tradeoffs |
| — | [ADRs](../adr/README.md) | Individual decisions and their reasoning |
| — | [Rules of engagement](../security/rules-of-engagement.md) | Binding scope for all security work |

## Diagram conventions

Diagrams are [Mermaid](https://mermaid.js.org/) and render natively on GitHub. Solid arrows are synchronous calls or hard dependencies. Dashed arrows are asynchronous, observational or soft dependencies.

## Change process

Architecture changes come as a PR touching this folder plus an ADR when a decision changes. The threat model is reviewed at every milestone that adds a trust boundary.
