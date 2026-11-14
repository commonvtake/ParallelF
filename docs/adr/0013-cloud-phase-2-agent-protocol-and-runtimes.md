# ADR-0013: Cloud Phase 2 — HTTP agent protocol, CLI-driven runtimes, one runtime per network

- Status: Accepted
- Date: 2026-11-13

## Context
[ADR-0006](0006-level-triggered-reconciliation.md) and the [cloud design](../architecture/subsystems/cloud.md) describe agents that fetch desired state over NATS request/reply, report over JetStream and heartbeat into a KV bucket, a libvirt driver on `go-libvirt`, and VMs and containers sharing one bridge through CNI and an agent-owned nftables table. Phase 2 must deliver a working single-host cloud on a 16 GB machine before the event backbone exists, with a node agent that is small, auditable and has no cgo or large dependency tree, and it must be testable in CI on hosted runners.

## Decision
1. **Agent protocol over HTTP.** The agent calls `POST /agent/v1/sync` on pf-cloudd (127.0.0.1:9102) every 3 s while anything is converging and every 10 s otherwise. The request carries host capacity, a metrics sample and the observed state of every workload; the response is the **complete** desired state for the node. This keeps ADR-0006's level-triggered model exactly: snapshot in, idempotent convergence, status out. The sync doubles as the heartbeat. Agents register once with a shared join token and receive a per-node credential (32 random bytes; pf-cloudd stores its SHA-256).
2. **Runtimes driven through their own interfaces, not client libraries.** The libvirt driver runs `virsh`, `qemu-img` and `genisoimage` with fixed argument lists (never a shell) and builds domain and network XML from typed Go structs; the Docker driver speaks the Engine API over the Unix socket with the standard library. The agent is standard-library only.
3. **libvirt networks for VMs, Docker networks for containers; a network belongs to one runtime.** NAT and isolation come from libvirt's and Docker's own rules; there is no agent-owned nftables table yet. Admission refuses a workload whose kind differs from the workloads already on its network.
4. **Images are fetched by the agent** from https URLs pinned by SHA-256 (VMs) or pulled by digest (containers); the catalogue is a migration, not an import API.

## Alternatives considered
- Deploy NATS now for the agent channel only: adds a service, credentials (NKeys) and failure modes to a phase whose goal is one host and one VM; the outbox already records events for when the backbone arrives.
- `go-libvirt` / `libvirtxml` and the Docker SDK: correct, but pull large dependency trees into a root daemon; `virsh` and the Engine HTTP API are stable, documented interfaces and easy to fake in tests.
- CNI-attached containers on libvirt bridges: allows mixed networks, but means owning IPAM inside CNI, veth plumbing and firewall rules — the riskiest code for the least Phase 2 value.

## Consequences
- Positive: one binary on the host with no third-party code; the whole agent is unit-tested with fake runtimes; CI boots real VMs with the same code. Swapping the transport for NATS later changes the client and one handler, not the reconciliation.
- Negative: polling costs a request every 10 s per node (negligible at this scale) and convergence starts up to one interval late; no push "poke". VMs and containers cannot share an L2 segment until a network provider replaces point 3. Removing a network depends on libvirt/Docker cleaning up their own rules.
- Revisit when: the event backbone lands (move sync to NATS request/reply plus JetStream status), or a second host or mixed networks are needed (VXLAN and CNI network provider).
