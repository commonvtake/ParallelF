import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pf_common.auth import InvalidTokenError, OIDCTokenVerifier, bearer_token

ISSUER = "http://localhost:8080/realms/parallelf"
AUDIENCE = "parallelf-api"


class StaticKeys:
    """Stands in for ``jwt.PyJWKClient``: resolves keys by ``kid``."""

    def __init__(self, keys: dict[str, Any]) -> None:
        self._keys = keys

    def get_signing_key_from_jwt(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys:
            raise jwt.PyJWKClientError(f"Unable to find a signing key that matches: {kid!r}")

        class _Key:
            key = self._keys[kid]

        return _Key()


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def verifier(private_key: rsa.RSAPrivateKey) -> OIDCTokenVerifier:
    return OIDCTokenVerifier(
        issuer=ISSUER,
        jwks_url="http://unused.test/certs",
        audience=AUDIENCE,
        key_source=StaticKeys({"key-1": private_key.public_key()}),
    )


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f",
        "aud": [AUDIENCE, "account"],
        "exp": now + 300,
        "iat": now,
        "typ": "Bearer",
        "preferred_username": "analyst",
        "email": "analyst@parallelf.test",
        "name": "Ana Analyst",
        "realm_access": {"roles": ["analyst", "offline_access"]},
    }
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not None}


def sign(key: rsa.RSAPrivateKey, payload: dict[str, Any], kid: str = "key-1") -> str:
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})


def test_valid_access_token_yields_principal(
    verifier: OIDCTokenVerifier, private_key: rsa.RSAPrivateKey
) -> None:
    principal = verifier.verify(sign(private_key, claims()))

    assert principal.subject == "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f"
    assert principal.username == "analyst"
    assert principal.email == "analyst@parallelf.test"
    assert principal.name == "Ana Analyst"
    assert principal.roles == ("analyst", "offline_access")


def test_optional_claims_have_safe_defaults(
    verifier: OIDCTokenVerifier, private_key: rsa.RSAPrivateKey
) -> None:
    token = sign(
        private_key,
        claims(preferred_username=None, email=None, name=None, realm_access=None, typ=None),
    )

    principal = verifier.verify(token)

    assert principal.username == principal.subject
    assert principal.email is None
    assert principal.roles == ()


@pytest.mark.parametrize(
    ("name", "overrides"),
    [
        ("expired", {"exp": int(time.time()) - 120}),
        ("wrong issuer", {"iss": "http://evil.example/realms/parallelf"}),
        ("wrong audience", {"aud": ["account"]}),
        ("missing audience", {"aud": None}),
        ("missing subject", {"sub": None}),
        ("missing expiry", {"exp": None}),
        ("id token", {"typ": "ID"}),
        ("refresh token type", {"typ": "Refresh"}),
    ],
)
def test_tokens_with_bad_claims_are_rejected(
    verifier: OIDCTokenVerifier,
    private_key: rsa.RSAPrivateKey,
    name: str,
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(private_key, claims(**overrides)))


def test_token_signed_by_another_key_is_rejected(
    verifier: OIDCTokenVerifier, other_key: rsa.RSAPrivateKey
) -> None:
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(other_key, claims(), kid="key-1"))
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(other_key, claims(), kid="unknown-key"))


def test_algorithm_confusion_is_rejected(
    verifier: OIDCTokenVerifier, private_key: rsa.RSAPrivateKey
) -> None:
    """HS256 signed with the RSA public key as the HMAC secret must fail."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "key-1"}).encode())
    payload = b64(json.dumps(claims()).encode())
    signature = b64(hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())

    with pytest.raises(InvalidTokenError):
        verifier.verify(f"{header}.{payload}.{signature}")


def test_unsigned_token_is_rejected(verifier: OIDCTokenVerifier) -> None:
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "JWT", "kid": "key-1"}).encode())
    payload = b64(json.dumps(claims()).encode())

    with pytest.raises(InvalidTokenError):
        verifier.verify(f"{header}.{payload}.")


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c"])
def test_garbage_is_rejected(verifier: OIDCTokenVerifier, token: str) -> None:
    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc.def.ghi", "abc.def.ghi"),
        ("bearer abc", "abc"),
        ("BEARER   abc  ", "abc"),
        ("Basic abc", None),
        ("Bearer", None),
        ("Bearer ", None),
        ("", None),
        (None, None),
    ],
)
def test_bearer_token(header: str | None, expected: str | None) -> None:
    assert bearer_token(header) == expected
