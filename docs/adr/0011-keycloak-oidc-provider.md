# ADR-0011: Keycloak as the OpenID Connect provider

- Status: Accepted
- Date: 2026-11-13
- Supersedes: [ADR-0008](0008-identity-service.md)

## Context
ADR-0008 chose to build identity (passwords, MFA, sessions, token issuance) inside `pf-core`, mainly to save memory and for the learning value. The Phase 1 brief instead requires authentication through an established OIDC provider. ADR-0008 had kept that door open: services depend only on a JWKS endpoint and standard token claims.

Self-built authentication is also the highest-risk code in the platform (risk R5), and it would have consumed the first weeks of the project before any subsystem existed.

## Decision
Use **Keycloak** as the identity provider.

- Users, credentials, MFA, sessions and token issuance belong to Keycloak. ParallelF stores no passwords.
- The dashboard is a confidential OIDC client using the authorization code flow with PKCE, implemented with the certified `openid-client` library. Tokens stay on the dashboard server.
- Go services verify access tokens with `coreos/go-oidc`; Python services with `PyJWT`. Both pin RS256 and check issuer, audience (`parallelf-api`) and expiry against the provider's JWKS.
- Platform roles are Keycloak realm roles (`realm_access.roles`). The role-to-permission mapping stays in ParallelF (`pkg/authz/permissions.json`).
- Token verification sits behind small interfaces (`authn.Verifier`, `TokenVerifier`). Reading roles from `realm_access` is the only Keycloak-specific code.

## Alternatives considered
- **Own identity service (ADR-0008):** lowest memory use, but the most security-sensitive code to write and maintain.
- **Dex:** very light, but it federates to other providers rather than managing users, MFA and roles itself.
- **Zitadel, Authentik, Ory:** capable; less widely deployed than Keycloak, so less transferable experience, and comparable setup effort.
- **A hosted provider (Auth0, Entra ID):** conflicts with the local-first requirement and adds an external dependency for sign-in.

## Consequences
- Positive: MFA (TOTP, passkeys), brute-force protection, account management and standard protocols come from a widely audited product; `pf-core` shrinks to profile, projects and, later, audit.
- Negative: Keycloak is a JVM service. Its container is capped at a 512 MB heap in the Compose stack, which is the largest single item in the Phase 1 memory budget. The figures in [08-infrastructure](../architecture/08-infrastructure.md) must be re-measured with it included.
- The sections of [platform-core.md](../architecture/subsystems/platform-core.md) that describe password hashing, token signing and refresh-token rotation inside `pf-core` no longer apply.
- Follow-ups: require MFA in the realm for production-like deployments; run Keycloak in production mode with PostgreSQL and TLS for lab-prod; service accounts become Keycloak clients using the client-credentials grant.
