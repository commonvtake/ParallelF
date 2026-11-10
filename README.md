# ParallelF
Integrated Cloud Infrastructure &amp; Network Security Platform

ParallelF is a self-hosted platform that combines a miniature cloud, a WireGuard VPN with a custom control plane, a network monitoring and defensive security system, an isolated game-security research lab, and a read-only AI investigation assistant, all managed from one dashboard.

| Subsystem | What it does | Core tech |
|---|---|---|
| **ParallelF Cloud** | Schedules and runs KVM virtual machines and containers on virtual networks through a custom control plane | Go, libvirt/KVM, Docker, Linux bridges, nftables |
| **ParallelF VPN** | WireGuard access with device enrolment, MFA-gated just-in-time access, policy firewalling and monitoring | Go, WireGuard (wgctrl), nftables |
| **ParallelF NetGuard** | Authorized discovery, telemetry, topology, detection, alerts and incident management | Zeek, Suricata, Go, Python, PostgreSQL, OpenSearch |
| **ParallelF Security Lab** | Isolated environments for defensive client/server-trust research on a self-built Unity game and educational vulnerable programs | Unity, C/C++, KVM isolation |
| **ParallelF AI** | Read-only, evidence-cited incident investigations | Python, FastAPI, Claude API |
| **ParallelF Dashboard** | Unified web interface | Next.js, React, TypeScript |

Shared foundation: PostgreSQL, NATS JetStream, Prometheus/Grafana, OpenTelemetry, k3s/Helm, Terraform (AWS).

## Status

🧭 **Architecture phase.** Start with [`docs/architecture/`](docs/architecture/README.md).

## Scope and ethics

All security work is limited to networks and software owned by the project author, under the [rules of engagement](docs/security/rules-of-engagement.md). The project builds defences. It does not build anti-cheat bypasses, stealth tooling, or capabilities aimed at third-party systems.
