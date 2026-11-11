# 00 — Assumptions, Scope, and Principles

Status: **Draft v0.1** · Owner: Vilarian Breaux · Last updated: 2026-11-10

This document records every assumption the architecture depends on. If an assumption turns out to be wrong, the linked sections are the ones to revisit.

## 1. Project framing

| Item | Assumption |
|---|---|
| Purpose | Portfolio-grade engineering project demonstrating cloud infrastructure, networking, distributed systems, and defensive security skills. |
| Operators | One owner/operator (you). The data model is still multi-project and role-based so that it reads as a real platform and so that least-privilege service accounts are possible. |
| Users | You plus devices you own. Optional invited reviewers (e.g. a recruiter given a read-only demo account). |
| Time budget | Part-time alongside classes and work: roughly 10–15 hrs/week. The roadmap is sized at ~43 working weeks (~10 months), with a defined "minimum resume-worthy slice" at ~6 months and a standalone-presentable Cloud subsystem at ~4 months. |
| Licence | Apache-2.0 recommended (patent grant, employer-friendly). Your call — see open questions. |

## 2. Environment assumptions

| Item | Assumption | Revisit in |
|---|---|---|
| Host OS | Windows 11 on i5-12400F (6P cores / 12 threads, **no iGPU**), 16 GB RAM, RTX 3060. | [08](08-infrastructure.md) |
| Linux runtime | WSL2 with Ubuntu 24.04 LTS, `systemd=true`, nested virtualization enabled, Docker Engine installed **inside** WSL (not Docker Desktop — saves ~1–2 GB RAM). | [08](08-infrastructure.md) |
| Hypervisor for "prod-like" node | Hyper-V VM running Ubuntu Server 24.04. **Requires Windows 11 Pro/Education/Enterprise.** If you are on Home edition, the fallback is a second WSL2 distro or a spare physical machine. | [08](08-infrastructure.md), [11](11-risks-and-tradeoffs.md) |
| Network | Your home LAN and router are yours; you can forward one UDP port (WireGuard) on the router. No scanning of networks you do not own or administer. | [07](07-trust-boundaries-and-threat-model.md) |
| AWS | Optional, ephemeral "cloud demo" environment only. Hard budget alarm at USD 10/month. Nothing runs 24/7 in AWS by default. | [08](08-infrastructure.md) |
| Claude API | You have (or will create) an Anthropic API key with a spend limit configured in the console. | [subsystems/ai.md](subsystems/ai.md) |
| Unity | Unity 6 LTS on Windows for development; the lab game ships Linux dedicated-server and Linux client builds so lab VMs stay light. | [subsystems/security-lab.md](subsystems/security-lab.md) |
| GPU | The RTX 3060 is used by the Windows host (Unity editor, local inference experiments). It is **not** passed through to nested VMs. | — |

## 3. Scope

### In scope (v1)

- A mini cloud with a custom control plane, scheduler and node agent that runs **KVM virtual machines** (via libvirt) and **containers** (via Docker Engine), on one physical host with the design ready for multiple nodes.
- Virtual networks (Linux bridges, IPAM, NAT/isolated/lab network types) shared by VMs and containers.
- A WireGuard VPN with a custom control plane, device enrolment, MFA-gated just-in-time access, policy-compiled nftables firewalling and connection monitoring.
- Passive network monitoring of **ParallelF-owned virtual networks** (VM bridges, the VPN interface) and optionally your own LAN, with Zeek + Suricata, plus scope-restricted active discovery.
- Detection rules, alert deduplication, incident management with evidence integrity.
- An isolated security lab running **your own** Unity game and **your own** deliberately vulnerable programs, focused on server authority, integrity validation, and documented mitigations.
- A read-only Claude-powered investigation assistant that produces cited, validated reports.
- A unified Next.js dashboard, a `pfctl` CLI, full observability and CI/CD.

### Explicitly out of scope

- Bypassing, evading or disabling any commercial anti-cheat (EAC, BattlEye, Vanguard, etc.), or interacting with third-party games or their online services.
- Stealth, persistence, rootkits, kernel drivers designed to hide activity, or any offensive tooling meant to leave the lab.
- Scanning or monitoring networks you do not own or have written authorization for.
- Writing custom cryptography. All crypto comes from WireGuard, Go's `crypto/*` and `golang.org/x/crypto`, WebCrypto, and well-known libraries.
- A custom VPN client. Clients use the official WireGuard apps.
- Live migration, distributed storage (Ceph), and GPU passthrough. They are listed as future extensions only.

## 4. Architectural principles

1. **Local-first, cost-conscious.** Everything runs on the dev box. Cloud resources are optional and disposable (`terraform destroy`).
2. **Level-triggered reconciliation over fire-and-forget commands.** Agents repeatedly converge actual state to desired state stored in PostgreSQL. A lost message delays convergence; it never corrupts state.
3. **One source of truth per fact.** PostgreSQL holds desired state and domain records. NATS JetStream carries change notifications and telemetry, and does not replace the database.
4. **Contracts first.** External APIs are defined in OpenAPI 3.1. Events are defined in Protobuf with `buf breaking` checks. Code is generated from the contracts.
5. **Modular monolith per bounded context.** Each subsystem ships as one control-plane binary with clean internal modules, plus small agents. This keeps the process count (and RAM) low while preserving boundaries that could later become separate services.
6. **Zero-trust internals.** Every hop is authenticated (mTLS, NATS NKeys, JWT re-verification). Services get least-privilege database roles and NATS subject permissions.
7. **Fail closed.** If the control plane is down, VPN access expires on its own (nftables set timeouts), discovery agents refuse to scan without a valid signed scope, and the AI cannot act at all.
8. **Observable by default.** Every service exposes metrics, structured logs with trace IDs, and health endpoints from its first commit.
9. **RAM is the scarcest resource.** Docker Compose profiles ensure that only the slice you are working on is running.
10. **Defensive, documented, reproducible security research.** Every lab experiment produces a finding, a mitigation, and a regression test or detection signal.

## 5. Open questions (non-blocking)

These do not block the architecture. The assumption in brackets is what the docs use until you answer.

1. **Windows edition:** Pro/Education (Hyper-V available) or Home? *[Assumed: Education/Pro]*
2. **Spare hardware:** Is there any old laptop or mini-PC that could become a dedicated Linux node? That would remove most nested-virtualization risk. *[Assumed: no]*
3. **Lab game:** Build a new small multiplayer game ("ParallelF Arena"), or adapt one of your existing Unity projects? *[Assumed: new, minimal, purpose-built for client/server trust research]*
4. **Licence:** Apache-2.0 or MIT? *[Assumed: Apache-2.0]*
