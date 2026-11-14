"""Fixtures for the integration tests.

These tests exercise the running local stack (``make up``) from the outside:
real tokens from the identity provider, the gateway's public API, the
dashboard's HTTP behaviour and the rows pf-core writes to PostgreSQL. Run
them with ``make test-integration``, which exports the settings in ``.env``.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]

GATEWAY_URL = os.environ.get("PF_GATEWAY_URL", "http://localhost:8000")
DASHBOARD_URL = os.environ.get("PF_DASHBOARD_URL", "http://localhost:3000")
KEYCLOAK_URL = os.environ.get("PF_KEYCLOAK_URL", "http://localhost:8080")
TOKEN_URL = f"{KEYCLOAK_URL}/realms/parallelf/protocol/openid-connect/token"

ContractCheck = Callable[[str, object], None]
ProjectFactory = Callable[..., dict[str, Any]]


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        pytest.fail(f"{name} is not set; run `make test-integration`, which loads .env")
    return value


def _password_grant(username: str, password: str, *, scope: str | None = None) -> dict[str, Any]:
    form = {
        "grant_type": "password",
        "client_id": "parallelf-dev-cli",
        "username": username,
        "password": password,
    }
    if scope:
        form["scope"] = scope
    response = httpx.post(TOKEN_URL, data=form, timeout=10)
    assert response.status_code == 200, f"token request for {username} failed: {response.text}"
    body: dict[str, Any] = response.json()
    return body


class _Tokens:
    """Access tokens per development user, renewed before they expire.

    Access tokens live five minutes; a full run (with the cloud tests that
    boot VMs) takes longer, so session-wide tokens would go stale.
    """

    MAX_AGE_S = 200

    def __init__(self) -> None:
        self._tokens: dict[str, tuple[str, float]] = {}

    def get(self, username: str, password_env: str) -> str:
        cached = self._tokens.get(username)
        if cached and time.monotonic() - cached[1] < self.MAX_AGE_S:
            return cached[0]
        token = str(_password_grant(username, _required_env(password_env))["access_token"])
        self._tokens[username] = (token, time.monotonic())
        return token


@pytest.fixture(scope="session")
def _tokens() -> _Tokens:
    return _Tokens()


@pytest.fixture
def owner_token(_tokens: _Tokens) -> str:
    """Access token of the development user with the ``owner`` role."""
    return _tokens.get("owner", "PF_DEV_OWNER_PASSWORD")


@pytest.fixture
def viewer_token(_tokens: _Tokens) -> str:
    """Access token of the development user with the ``viewer`` role."""
    return _tokens.get("viewer", "PF_DEV_VIEWER_PASSWORD")


@pytest.fixture(scope="session")
def owner_id_token() -> str:
    """An ID token: validly signed, but not a credential for the API."""
    tokens = _password_grant("owner", _required_env("PF_DEV_OWNER_PASSWORD"), scope="openid")
    return str(tokens["id_token"])


@pytest.fixture
def owner_headers(owner_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {viewer_token}"}


@pytest.fixture(scope="session")
def dashboard_url() -> str:
    return DASHBOARD_URL


@pytest.fixture(scope="session")
def keycloak_url() -> str:
    return KEYCLOAK_URL


@pytest.fixture
def gateway() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=GATEWAY_URL, timeout=10) as client:
        yield client


@pytest.fixture
def dashboard() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=DASHBOARD_URL, timeout=10, follow_redirects=False) as client:
        yield client


@pytest.fixture(scope="session")
def contract() -> ContractCheck:
    """Validate a response body against a schema of the OpenAPI contract."""
    spec_path = REPO_ROOT / "api" / "openapi" / "parallelf.v1.yaml"
    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))

    def check(schema_name: str, instance: object) -> None:
        assert schema_name in spec["components"]["schemas"], f"unknown schema {schema_name}"
        schema = {
            "$ref": f"#/components/schemas/{schema_name}",
            "components": spec["components"],
        }
        errors = [error.message for error in Draft202012Validator(schema).iter_errors(instance)]
        assert not errors, f"response does not match {schema_name}: {errors}"

    return check


@pytest.fixture
def database() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """A connection as pf-core's runtime role, to inspect what it stored."""
    url = os.environ.get("PF_TEST_DATABASE_URL") or (
        f"postgresql://pf_core:{_required_env('PF_CORE_DB_PASSWORD')}"
        f"@localhost:{os.environ.get('PF_POSTGRES_HOST_PORT', '5432')}/parallelf"
    )
    with psycopg.connect(url, autocommit=True, connect_timeout=10) as connection:
        yield connection


@pytest.fixture
def make_project(gateway: httpx.Client, _tokens: _Tokens) -> Iterator[ProjectFactory]:
    """Create projects through the API; they are deleted after the test."""
    created: list[str] = []
    counter = iter(range(1000))

    def owner() -> dict[str, str]:
        # Fetched per call: the cleanup may run long after the test started.
        return {"Authorization": f"Bearer {_tokens.get('owner', 'PF_DEV_OWNER_PASSWORD')}"}

    def create(**overrides: str) -> dict[str, Any]:
        body = {
            "slug": f"it-{os.urandom(5).hex()}-{next(counter)}",
            "name": "Integration test",
            **overrides,
        }
        response = gateway.post("/api/v1/core/projects", json=body, headers=owner())
        assert response.status_code == 201, response.text
        project: dict[str, Any] = response.json()
        created.append(project["id"])
        return project

    yield create

    for project_id in created:
        gateway.delete(f"/api/v1/core/projects/{project_id}", headers=owner())
