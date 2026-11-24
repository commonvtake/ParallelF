# ADR-0014: VPN Phase 3 — long-poll sync, CLI-driven WireGuard and nftables

- Status: Accepted
- Date: 2026-11-24

## Context
The [VPN design](../architecture/subsystems/vpn.md) has the gateway agent fetch desired state over NATS request/reply after a "poke", report over JetStream, and drive the kernel with `wgctrl` and `google/nftables`. As in Phase 2 ([ADR-0013](0013-cloud-phase-2-agent-protocol-and-runtimes.md)), NATS is not deployed yet, the agent runs as root and should carry no third-party code, and revocation must reach the gateway in under 10 s.

## Decision
1. **HTTP long-poll instead of poke + request.** The agent posts its observations to `/agent/v1/sync` with the revision it last applied; pf-vpnd answers at once if the desired state is newer, or holds the request (up to 25 s) until a change commits. Every change that matters to a gateway bumps `vpn.state.revision` in its transaction and wakes waiters in-process. This gives sub-second revocation without a message bus.
2. **`wg`, `ip`, `nft` and `conntrack` with fixed argument lists**, standard library only. The nftables table is rendered from validated, structured values (addresses, CIDRs, ports parsed and re-printed) and applied as one `nft -f` transaction; activations are updated element by element. Pre-shared keys go to `wg` on stdin.
3. **Device groups start as the owner's platform roles.** Policies refer to groups; managers can regroup devices. No separate group objects yet.
4. **Step-up by sign-in freshness.** Activation requires `auth_time` within 15 minutes, with an optional `amr` second-factor requirement, instead of mandatory MFA, because the development identity provider has no second factor configured.

## Alternatives considered
- Short polling (every 1-2 s): simpler, but costs a query per second per gateway and still adds latency.
- PostgreSQL LISTEN/NOTIFY to wake waiters: needed once pf-vpnd runs more than one replica; in-process notification is enough for one.
- `google/nftables`: avoids the CLI, but brings a netlink dependency into a root daemon; `nft -f` gives the same atomicity.

## Consequences
- Positive: revocation measured at well under a second; the agent is small and fully unit-tested with a fake runner; the generated ruleset is also checked by the real `nft` parser.
- Negative: one pf-vpnd replica (wake-ups are in-process); devices on one gateway; no DNS yet.
- Revisit when: the event backbone lands (move sync to NATS), pf-vpnd needs replicas (LISTEN/NOTIFY), or a second gateway is added.
