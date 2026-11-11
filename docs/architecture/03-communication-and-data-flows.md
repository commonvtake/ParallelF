# 03 — Service Communication and Data Flows

Flows specific to one subsystem live in its own doc: [VPN enrolment](subsystems/vpn.md#3-device-enrolment--the-private-key-never-leaves-the-device), [AI investigation](subsystems/ai.md#4-orchestration-loop), [lab experiment](subsystems/security-lab.md#6-experiment-workflow). This document covers the cross-cutting and cross-subsystem flows.

## 1. Communication matrix

| From \ To | pf-core | pf-cloudd | pf-vpnd | pf-netguardd | pf-labd | pf-aid | NATS | Postgres |
|---|---|---|---|---|---|---|---|---|
| **pf-gateway** | REST (auth, JWKS) | REST | REST | REST | REST | REST | sub (SSE fan-out) | — |
| **pf-core** | — | — | — | — | — | — | pub outbox, sub `pf.audit.>` | `core`, `audit` |
| **pf-cloudd** | JWKS | — | — | — | — | — | pub events, req/reply agents, KV | `cloud` |
| **pf-vpnd** | JWKS | REST (resolve network CIDRs) | — | — | — | — | pub events, req/reply agents | `vpn` |
| **pf-netguardd** | JWKS | — | — | — | — | — | sub telemetry/alerts/cloud/vpn events | `netguard` |
| **pf-ng-detect** | — | — | — | — | — | — | sub telemetry, pub alerts | `netguard` read-only views (documented exception, [05](05-database-design.md) §1) |
| **pf-labd** | client-credentials | **REST (create lab nets/VMs)** | — | REST (sensor health) | — | — | pub events, sub integrity | `lab` |
| **pf-aid** | client-credentials | REST read | REST read | **REST read** | REST read | — | pub events | `ai` |
| **pf-node-agent** | — | — | — | — | — | — | req desired, pub status, KV heartbeat | — |
| **pf-wg-agent** | — | — | — | — | — | — | req desired, pub stats/events | — |
| **pf-ng-shipper / discovery** | — | — | — | — | — | — | pub telemetry, req scope | — |

Rules:

- Services never read another service's schema. Cross-domain data comes through REST APIs or events. The single exception is `pf-ng-detect`, which reads three NetGuard views (it is a satellite worker of the NetGuard domain, not a separate domain).
- Agents talk **only** to NATS. They have no DB credentials and no inbound ports.
- Every REST hop is mTLS. Every NATS identity is an NKey user with explicit subject permissions ([07](07-trust-boundaries-and-threat-model.md) §5).

## 2. Request path: browser → service

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant D as Dashboard BFF
    participant G as pf-gateway
    participant S as pf-cloudd
    participant P as Postgres
    participant J as JetStream
    participant C as pf-core (audit)
    B->>D: POST /bff/api/cloud/workloads (cookie + CSRF token)
    D->>D: session lookup, refresh access token if < 60 s left
    D->>G: POST /api/v1/cloud/workloads (Bearer JWT, Idempotency-Key, traceparent)
    G->>G: verify JWT (cached JWKS), rate limit, route permission check
    G->>S: mTLS proxy + Authorization
    S->>S: re-verify JWT, fine-grained authz (project role), validate body
    S->>P: tx: quota check, insert workload + operation + outbox rows
    S-->>G: 202 Accepted {operation}
    G-)J: publish pf.audit.http (who, what, outcome)
    G-->>D: 202
    D-->>B: 202
    S-)J: outbox relay publishes pf.cloud.evt.workload.created
    J-)C: audit consumer appends hash-chained record
```

## 3. VM creation end to end

```mermaid
sequenceDiagram
    autonumber
    participant API as cloudd/api
    participant SCH as cloudd/scheduler
    participant REC as cloudd/reconciler
    participant N as NATS
    participant AG as pf-node-agent
    participant LV as libvirt/KVM
    participant NG as pf-netguardd
    API->>API: workload PENDING (generation 1)
    API-)SCH: notify (outbox event workload.created)
    SCH->>SCH: filter → score → bind (FOR UPDATE on node)
    SCH-)REC: workload.scheduled
    REC-)N: pf.cloud.node.n1.poke
    N-)AG: poke
    AG->>N: req pf.cloud.node.n1.desired
    N->>REC: forward request
    REC-->>AG: DesiredNodeState{rev 42}
    AG->>AG: ensure bridge pfbr-x, nft table, cached base image
    AG->>LV: create qcow2 overlay + seed ISO, define + start domain
    AG-)N: status {observed_generation 1, state PROVISIONING}
    LV-->>AG: domain running, DHCP lease / guest ping
    AG-)N: status {state RUNNING, ip 10.20.1.15}
    N-)REC: consume status → update workload, outbox workload.state_changed
    REC-)NG: event (via JetStream) → asset/attribution: 10.20.1.15 = workload w-123
```

## 4. Telemetry → alert → incident → AI

```mermaid
flowchart LR
    PKT["packets on pfbr-* / wg-pf0"] --> ZK["Zeek"] & SU["Suricata"]
    ZK & SU --> SH["pf-ng-shipper"]
    SH -- "pf.ng.tel.s1.conn / dns / alert" --> JS[("PF_NG_TELEMETRY")]
    JS -- "consumer: ingest" --> ING["netguardd ingest"] --> FL[("flows, dns_events …")]
    JS -- "consumer: detect" --> DET["pf-ng-detect"]
    DET -- "pf.ng.alert.candidate" --> AJS[("PF_NG_ALERTS")]
    AJS --> ALR["netguardd alerts<br/>dedupe + enrich (attribution)"]
    ALR --> CORR{"correlate<br/>same asset ≤ 30 min,<br/>sev ≥ medium"}
    CORR -- yes --> INC["incident (proposed)"]
    INC -- "analyst: Investigate" --> AI["pf-aid"]
    AI -- "read tools" --> FL
    AI --> REP["report (validated / needs_review)"]
    REP -- "analyst approves" --> INC
```

Latency budget (p95): Zeek log flush ≤ 10 s (Zeek's rotation/flush interval tuned down for dev), shipper ≤ 1 s, ingest batch ≤ 1 s, detection ≤ 5 s, alert upsert ≤ 1 s. The total stays under the 30 s target for flows, and under 60 s for alerts.

## 5. VPN JIT activation (fail-closed path)

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant D as Dashboard
    participant V as pf-vpnd
    participant A as pf-wg-agent
    participant K as Kernel nftables
    U->>D: "Activate Pixel for 8h"
    D->>D: session MFA older than 15 min? → step-up (TOTP/WebAuthn)
    D->>V: POST /vpn/devices/{id}/activate {ttl: 8h} (amr includes otp)
    V->>V: check policy max TTL, record activation, outbox + audit
    V-)A: poke
    A->>V: desired (activations with absolute expiry)
    A->>K: add element { 10.255.0.12 timeout 7h59m50s } to @active_peers
    Note over K: Expiry is enforced by the kernel.<br/>If V, NATS and Postgres all die, access still ends on time.
    K-->>K: element expires → traffic dropped
    A-)V: event peer.jit_expired (on next reconcile)
```

The agent computes the remaining timeout from the **absolute** expiry, so restarts never extend access. On restart it rebuilds the set from desired state, and expired activations are simply absent.

## 6. Lab telemetry relay (one-way)

```mermaid
flowchart LR
    GS["arena-server VM"] -- "virtio-serial<br/>length-prefixed protobuf" --> RL["host relay<br/>(part of pf-node-agent, lab module)"]
    RL -- "validate schema, size ≤ 16 KiB,<br/>rate ≤ 50 msg/s" --> J[("pf.lab.integrity.<env_id>")]
    J --> LABD["pf-labd"] --> LDB[("lab.integrity_reports")]
    J --> DET["pf-ng-detect<br/>lab.game_integrity"]
    RL -. "nothing flows back into the VM" .-x GS
```

## 7. Event flow map (producers → consumers)

| Stream | Subjects | Producers | Consumers |
|---|---|---|---|
| `PF_AUDIT` | `pf.audit.>` | gateway, all services, agents | `pf-core` audit writer |
| `PF_CLOUD_EVENTS` | `pf.cloud.evt.>` | `pf-cloudd` (outbox) | netguardd (attribution), vpnd (network CIDRs), labd (env status), gateway SSE |
| `PF_AGENT_STATUS` | `pf.cloud.node.*.status`, `pf.vpn.gw.*.status` | node agents, wg agents | cloudd, vpnd |
| `PF_VPN_EVENTS` | `pf.vpn.evt.>` | `pf-vpnd` (outbox), `pf-wg-agent` (connect/disconnect) | netguardd (attribution), gateway SSE |
| `PF_VPN_STATS` | `pf.vpn.gw.*.stats` | `pf-wg-agent` | vpnd (peer_stats) |
| `PF_NG_TELEMETRY` | `pf.ng.tel.>` | shipper, discovery, probe | netguardd ingest + inventory, ng-detect |
| `PF_NG_ALERTS` | `pf.ng.alert.>` | ng-detect | netguardd alerts |
| `PF_NG_EVENTS` | `pf.ng.evt.>` | netguardd (outbox: alert/incident changes) | gateway SSE, aid (optional auto-triage, off by default) |
| `PF_LAB` | `pf.lab.evt.>`, `pf.lab.integrity.>` | labd, lab relay | labd, ng-detect, gateway SSE |
| `PF_AI_EVENTS` | `pf.ai.evt.>` | aid | gateway SSE, netguardd (report ready) |
| `PF_DLQ` | `pf.dlq.>` | consumer libs | humans (alert) |

Core NATS (non-persistent) subjects are used for request/reply and pokes: `pf.cloud.node.<id>.desired`, `pf.cloud.node.<id>.poke`, `pf.vpn.gw.<id>.desired`, `pf.vpn.gw.<id>.poke`, `pf.ng.sensor.<id>.scope`.
