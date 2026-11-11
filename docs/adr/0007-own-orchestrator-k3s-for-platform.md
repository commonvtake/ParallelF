# ADR-0007: Own workload orchestrator; k3s only for deploying the platform

- Status: Accepted
- Date: 2026-11-10

## Context
ParallelF Cloud must run both VMs and containers. Kubernetes is in the preferred stack, and the project's learning value is in building a control plane.

## Decision
- ParallelF Cloud uses its **own** API, scheduler and node agent with libvirt/KVM and Docker drivers.
- **k3s + Helm** is used to deploy the ParallelF platform services in lab-prod and cloud-demo (production-like operations: NetworkPolicies, PSA, probes, rolling upgrades).
- A future `k8s` driver could schedule container workloads into a k3s namespace through the same Driver interface.

## Alternatives considered
- KubeVirt on Kubernetes for VMs: production-grade, but far too heavy for 16 GB, and it would replace the part of the project worth building.
- Nomad: lighter, but still replaces the scheduler.
- Full kubeadm / EKS: heavier or costly; k3s is a CNCF-certified distribution suited to small nodes.

## Consequences
- Positive: demonstrates scheduler/reconciler/virtual-networking design *and* real Kubernetes operations.
- Negative: two orchestration layers to understand; agents must coexist with k3s networking (separate nftables tables).
