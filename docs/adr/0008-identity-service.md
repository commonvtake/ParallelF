# ADR-0008: Own identity service on standard primitives

- Status: Superseded by [ADR-0011](0011-keycloak-oidc-provider.md)
- Date: 2026-11-10

## Context
The platform needs users, MFA (TOTP + WebAuthn), sessions, service accounts, API tokens, RBAC and audit. Off-the-shelf IdPs exist but cost RAM (Keycloak typically needs several hundred MB to 1 GB+) and add operational surface.

## Decision
Build `pf-core` using only established primitives and libraries: argon2id (`golang.org/x/crypto/argon2`), EdDSA JWTs (`lestrrat-go/jwx`), TOTP (`pquerna/otp`), WebAuthn (`go-webauthn/webauthn`), `crypto/rand`, AES-GCM. **No custom crypto.** Downstream services depend only on JWKS + standard claims, so `pf-core`'s token issuance can later be replaced by an OIDC provider without changing them.

## Alternatives considered
- Keycloak: feature-complete; heavy JVM footprint.
- Zitadel / Authentik / Ory (Kratos + Hydra): lighter, but still extra services and their own databases; less learning value.

## Consequences
- Positive: small footprint; deep understanding of auth flows is demonstrable.
- Negative: higher risk of subtle security bugs, so this area gets the strictest test matrix (M2) and review (M16). Revisit if the platform ever has real external users.
