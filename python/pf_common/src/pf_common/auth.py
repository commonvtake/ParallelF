"""OIDC access-token verification.

Tokens are JWTs signed by the identity provider. Verification uses PyJWT:
the signature is checked against the provider's published keys (JWKS) with
the algorithm pinned to RS256, and the issuer, audience and expiry claims
are enforced. Platform roles come from Keycloak's ``realm_access.roles``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import jwt

ALGORITHMS = ["RS256"]
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]


class InvalidTokenError(Exception):
    """The token must be rejected. The message is for logs, never for clients."""


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    subject: str
    username: str
    email: str | None = None
    name: str | None = None
    roles: tuple[str, ...] = ()


class TokenVerifier(Protocol):
    """Validates a raw bearer token."""

    def verify(self, token: str) -> Principal:
        """Return the caller, or raise :class:`InvalidTokenError`."""
        ...


class SigningKeySource(Protocol):
    """Finds the public key that signed a token (``jwt.PyJWKClient`` does)."""

    def get_signing_key_from_jwt(self, token: str) -> Any: ...


class OIDCTokenVerifier:
    """Verifies access tokens against an identity provider's JWKS."""

    def __init__(
        self,
        *,
        issuer: str,
        jwks_url: str,
        audience: str,
        key_source: SigningKeySource | None = None,
        leeway_seconds: int = 30,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds
        # Keys are fetched lazily and cached, so the provider may start later.
        self._keys: SigningKeySource = key_source or jwt.PyJWKClient(
            jwks_url, cache_keys=True, lifespan=300, timeout=5
        )

    def verify(self, token: str) -> Principal:
        try:
            signing_key = self._keys.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=ALGORITHMS,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc) or type(exc).__name__) from exc

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise InvalidTokenError("missing sub claim")

        # Keycloak marks access tokens with typ=Bearer and ID tokens with typ=ID.
        token_type = claims.get("typ")
        if token_type is not None and str(token_type).lower() != "bearer":
            raise InvalidTokenError(f"token type {token_type!r} is not an access token")

        realm_access = claims.get("realm_access")
        raw_roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
        roles = tuple(role for role in raw_roles if isinstance(role, str))

        username = claims.get("preferred_username")
        return Principal(
            subject=subject,
            username=username if isinstance(username, str) and username else subject,
            email=_optional_str(claims.get("email")),
            name=_optional_str(claims.get("name")),
            roles=roles,
        )


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an ``Authorization: Bearer`` header value."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token
