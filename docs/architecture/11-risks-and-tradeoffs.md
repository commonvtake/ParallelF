# 11 — Major Technical Risks and Engineering Tradeoffs

## 1. Risk register

Likelihood (L) and Impact (I): H/M/L. Each risk has an early-warning signal and the milestone where it gets retired or confirmed.

| # | Risk | L | I | Mitigation | Early signal / retire by |
|---|---|---|---|---|---|
| R1 | **RAM exhaustion** on 16 GB (Windows + WSL + VMs + Unity) | H | H | Compose profiles; `mem-report.sh`; binpack scheduling; OpenSearch opt-in; Next.js prod build when not editing UI; `pf.nano` flavors; modes A/B | WSL OOM-kills or Windows paging → measure in **M0**; re-measure each milestone |
| R2 | **Nested KVM in WSL2** is unavailable, flaky or slow | M | H | Container driver first (M4), so Cloud progresses regardless; VM driver behind an interface; fallback to Hyper-V VM (mode B) or a spare/dual-boot Linux machine | `check-nested-virt.sh` in **M0**; VM boot p95 in **M5** |
| R3 | **WSL2 networking quirks** (NAT vs mirrored mode, inbound UDP for WireGuard, Hyper-V firewall) | M | M | Mirrored mode; documented firewall rule; lab-prod gateway on a Hyper-V VM with an external switch | Phone-on-cellular test in **M7** |
| R4 | **Scope creep / burnout**: six subsystems is a lot for one student | H | H | Vertical slices; cut lines defined; minimum resume-worthy slice; demo + tag every milestone; no gold-plating before M10 | Milestone slips > 50% → apply cut lines |
| R5 | **Security bugs in self-built identity** | M | H | Standard libraries only (argon2id, jose/jwx, go-webauthn, otp); exhaustive JWT/RBAC tests; JWKS-based design keeps a swap to Keycloak/Zitadel cheap ([ADR-0008](../adr/0008-identity-service.md)) | Test matrix in **M2**; review in **M16** |
| R6 | **Event-driven consistency bugs** (lost/duplicate events, ordering) | M | H | Outbox + dedupe + idempotent consumers + level-triggered reconciliation; crash tests in M1 and chaos tests in M16 | M1 crash-test AC |
| R7 | **Telemetry volume vs Postgres** | M | M | Daily partitions, COPY batching, BRIN, short retention; OpenSearch optional; detection works off the stream, not the DB | M9 throughput AC |
| R8 | **Zeek/Suricata resource use and tuning** | M | M | Single Zeek worker, trimmed Suricata ruleset, sensors only in `ng` profiles, monitor bridges only | M9/M10 RSS measurements |
| R9 | **Lab isolation failure** | L | H | Defence in depth ([security-lab.md](subsystems/security-lab.md) §3); isolation suite at every start; critical alert; only educational self-authored code | M11 isolation AC |
| R10 | **Unity complexity** (netcode, Linux headless builds, IL2CPP toolchains, Git LFS quota of 1 GB on free GitHub) | M | M | Deliberately tiny game; primitives-only art; bots for testing; keep Unity in a submodule or separate repo if LFS grows | M12 start: repo size check |
| R11 | **Claude API cost, latency, nondeterminism** | M | M | Budgets; prompt caching; Sonnet-class default; offline evals on recorded tool outputs; deterministic validator decides "validated" | M13 eval metrics |
| R12 | **Prompt injection** through telemetry | H (attempts) | L (impact) | Read-only tools; validator; sanitized rendering; human approval ([ai.md](subsystems/ai.md) §7) | M13 injection corpus |
| R13 | **Polyglot overhead** (Go, Python, TS, C++, C#) | H | M | Contract-first codegen; shared libs per language; Go for all control planes and agents except where Python libraries matter; C++ confined to optional probe + lab targets | Build/CI time > 15 min → split workflows |
| R14 | **Legal/ethical misuse perception** (scanning, game hacking) | L | H | Rules of engagement; signed scopes; public-IP hard block; defensive framing in every write-up; no third-party targets | Review README + write-ups before publishing |
| R15 | **AWS surprise bills** | L | M | No NAT gateway, ephemeral environment, budget alarms, `verify-clean`, tagged resources | M15 AC |
| R16 | **Upstream drift** (WSL settings, k3s, Unity, Claude API models) | M | L | Pin versions; model IDs in config; version matrix in [08](08-infrastructure.md) §10 | Dependabot PRs |

## 2. Key tradeoffs

| Decision | Chosen | Alternatives considered | Why (and what we give up) |
|---|---|---|---|
| Workload orchestration | **Own control plane + scheduler** over libvirt and Docker | Kubernetes + KubeVirt; OpenStack; Nomad | The point of the project is building the control plane. KubeVirt and OpenStack are far too heavy for 16 GB. We give up maturity and features (migration, HA) |
| Platform deployment | **Docker Compose (dev) + k3s/Helm (lab-prod)** | kind, minikube, full kubeadm, EKS | k3s is a real, lightweight distribution. EKS costs control-plane fees 24/7. Two deployment paths have to be maintained |
| Service granularity | **Modular monolith per bounded context** (~12 deployables) | Microservice per function (25+) | RAM and operational simplicity, while the boundaries stay real. Modules can't be scaled independently, which doesn't matter at this scale ([ADR-0003](../adr/0003-modular-monolith-per-domain.md)) |
| Messaging | **NATS JetStream** | Kafka, Redpanda, RabbitMQ, Redis Streams | Single small binary with streams, KV, request/reply and fine-grained auth. Kafka-class tooling and ecosystem are given up ([ADR-0002](../adr/0002-nats-jetstream.md)) |
| Control → agent protocol | **Level-triggered desired-state snapshots** | Command queue; gRPC streaming | Robust to loss, reordering and restarts. Snapshots cost more bandwidth (negligible at this scale) ([ADR-0006](../adr/0006-level-triggered-reconciliation.md)) |
| Data store layout | **One Postgres, schema per service, no cross-schema FKs** | DB per service; shared schema | Low RAM with ownership boundaries kept. The trade is a shared failure domain and no cross-domain referential integrity ([ADR-0004](../adr/0004-postgres-schema-per-service.md)) |
| Telemetry store | **Postgres partitions by default; OpenSearch opt-in** | OpenSearch-only; ClickHouse; TimescaleDB | Fits the RAM budget and keeps one query language. Postgres gives up full-text search and heavy aggregations unless OpenSearch is on ([ADR-0009](../adr/0009-postgres-first-telemetry.md)) |
| External API | **REST + OpenAPI 3.1** | gRPC-web; GraphQL | Browser-friendly, cacheable, easy to demo with curl. Streaming RPC is given up (SSE covers it) |
| Event encoding | **Protobuf schemas, protojson on the wire** | Binary protobuf; JSON Schema | Schema evolution checks (`buf breaking`) plus human-readable messages. Payloads are larger (fine at this scale; binary is reserved via `content-type`) |
| Identity | **Own `pf-core` built on standard primitives** | Keycloak, Zitadel, Authentik, Ory | Shows understanding of auth and is light on RAM. It is also riskier, which is mitigated by tests and a swappable JWKS interface ([ADR-0008](../adr/0008-identity-service.md)) |
| Gateway | **Small custom Go gateway** | Envoy, Traefik, Kong | Tight integration with RBAC, audit, SSE and console tickets. Advanced L7 features are given up ([ADR-0005](../adr/0005-custom-go-gateway.md)) |
| Web auth | **BFF with server-side tokens** | SPA holding tokens in memory/localStorage | XSS cannot steal tokens. The dashboard server becomes stateful (a session store) |
| Container networking | **CNI bridge plugin into shared Linux bridges** | Docker bridge networks; macvlan | VMs and containers share L2 and IPAM. It is more custom wiring than plain Docker networks |
| libvirt bindings | **`digitalocean/go-libvirt` (pure Go RPC)** | `libvirt.org/go/libvirt` (cgo) | No cgo, easy cross-builds. Some API conveniences are lost |
| Network sensors | **Zeek + Suricata**, optional C++ probe | Own C++ DPI only; ntopng | Industry-standard tools recruiters recognize, plus `community_id` correlation. Their RAM cost is the trade |
| VPN access gating | **nftables timeout sets for JIT** | Remove/add peers on schedule from control plane | Expiry is enforced by the kernel and fails closed. The trade is more nftables complexity |
| VPN key generation | **On the client (browser WebCrypto / WG app / pfctl)** | Server-generated keys | The private key never exists server-side. A slightly more complex UX |
| Lab workloads | **VMs only, isolated `lab` networks** | Containers; Windows VMs | A stronger boundary and lower RAM (Linux guests). Windows-only tooling is given up inside the lab |
| AI output trust | **Deterministic citation validator + human approval** | Trust the model; LLM-as-judge | Verifiable and cheap. Some correct but uncited insights get flagged `needs_review` |
| AI model | **Configurable, Sonnet-class default** | Always the largest model | Cost/latency balance; a deep mode is available on demand |

## 3. Things deliberately deferred

Live migration · shared/distributed storage (Ceph) · GPU passthrough · multi-region · HA control plane (multi-replica with leader election is designed for, but runs single-replica) · per-project overlapping CIDRs (needs network namespaces/VRFs per project) · custom VPN client · SSO federation (GitHub OIDC login is a natural first add-on) · GitOps controller · Windows lab guests.
