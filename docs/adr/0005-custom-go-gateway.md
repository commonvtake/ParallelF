# ADR-0005: Custom Go API gateway

- Status: Accepted
- Date: 2026-11-10

## Context
The edge must verify EdDSA JWTs against a JWKS, enforce a route → permission table generated from `permissions.yaml`, emit audit events to NATS, fan out RBAC-filtered SSE, and proxy VM consoles with single-use tickets.

## Decision
Build `pf-gateway` in Go on `net/http` + `httputil.ReverseProxy`, reusing the shared `pkg/authn`, `pkg/authz`, `pkg/events` and `pkg/obs` libraries.

## Alternatives considered
- Envoy (+ ext_authz): powerful, but heavier, and audit/SSE/console logic would still need custom services.
- Traefik / Kong plugins: good for routing, awkward for NATS-backed SSE and audit.

## Consequences
- Positive: small footprint; one place for edge security logic; a strong learning and demo piece.
- Negative: we own the correctness of the edge (mitigated by exhaustive tests); fewer L7 features (retries, circuit breaking added only as needed).
