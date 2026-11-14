"""Token verification with real tokens from the identity provider."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

ContractCheck = Callable[[str, object], None]

# One route served by the Go service and one served by the Python service:
# both verify tokens themselves, behind the gateway's own check.
PROTECTED_ROUTES = ["/api/v1/core/me", "/api/v1/ai/info"]


@pytest.mark.parametrize("route", PROTECTED_ROUTES)
def test_request_without_token_is_rejected(
    gateway: httpx.Client, contract: ContractCheck, route: str
) -> None:
    response = gateway.get(route)

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    body = response.json()
    contract("Problem", body)
    assert body["type"] == "https://parallelf.dev/problems/unauthorized"
    assert body["request_id"] == response.headers["x-request-id"]


@pytest.mark.parametrize("route", PROTECTED_ROUTES)
def test_malformed_token_is_rejected(gateway: httpx.Client, route: str) -> None:
    response = gateway.get(route, headers={"Authorization": "Bearer not-a-jwt"})

    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers["www-authenticate"]


def test_token_with_a_modified_payload_is_rejected(gateway: httpx.Client, owner_token: str) -> None:
    header, payload, signature = owner_token.split(".")
    # Change one character of the signed payload; the signature no longer matches.
    replacement = "A" if payload[10] != "A" else "B"
    tampered = ".".join([header, payload[:10] + replacement + payload[11:], signature])

    response = gateway.get("/api/v1/core/me", headers={"Authorization": f"Bearer {tampered}"})

    assert response.status_code == 401


@pytest.mark.parametrize("route", PROTECTED_ROUTES)
def test_id_token_is_not_accepted_as_an_access_token(
    gateway: httpx.Client, owner_id_token: str, route: str
) -> None:
    response = gateway.get(route, headers={"Authorization": f"Bearer {owner_id_token}"})

    assert response.status_code == 401


def test_owner_profile(
    gateway: httpx.Client, owner_headers: dict[str, str], contract: ContractCheck
) -> None:
    response = gateway.get("/api/v1/core/me", headers=owner_headers)

    assert response.status_code == 200
    me = response.json()
    contract("Me", me)
    assert me["username"] == "owner"
    assert me["email"] == "owner@parallelf.test"
    assert me["roles"] == ["owner"]
    assert "core.projects.create" in me["permissions"]
    assert "core.projects.delete" in me["permissions"]


def test_viewer_profile_has_read_permissions_only(
    gateway: httpx.Client, viewer_headers: dict[str, str], contract: ContractCheck
) -> None:
    response = gateway.get("/api/v1/core/me", headers=viewer_headers)

    assert response.status_code == 200
    me = response.json()
    contract("Me", me)
    assert me["roles"] == ["viewer"]
    assert me["permissions"] == ["cloud.resources.read", "core.projects.read", "system.status.read"]
