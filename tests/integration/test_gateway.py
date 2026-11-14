"""Gateway behaviour: health, routing, error format and platform status."""

from __future__ import annotations

from collections.abc import Callable

import httpx

ContractCheck = Callable[[str, object], None]


def test_liveness_matches_the_contract(gateway: httpx.Client, contract: ContractCheck) -> None:
    response = gateway.get("/healthz")

    assert response.status_code == 200
    contract("Health", response.json())
    assert response.json()["service"] == "pf-gateway"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_readiness_matches_the_contract(gateway: httpx.Client, contract: ContractCheck) -> None:
    response = gateway.get("/readyz")

    assert response.status_code == 200
    contract("Health", response.json())
    assert response.json()["status"] == "ok"


def test_every_response_carries_a_request_id(gateway: httpx.Client) -> None:
    generated = gateway.get("/healthz").headers["x-request-id"]
    assert len(generated) == 36

    echoed = gateway.get("/healthz", headers={"X-Request-ID": "integration-test-0001"})
    assert echoed.headers["x-request-id"] == "integration-test-0001"


def test_unknown_route_is_a_problem_document(
    gateway: httpx.Client, contract: ContractCheck
) -> None:
    response = gateway.get("/no/such/route")

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    contract("Problem", body)
    assert body["type"] == "https://parallelf.dev/problems/not-found"
    assert body["request_id"] == response.headers["x-request-id"]


def test_unknown_api_domain_is_not_routed(
    gateway: httpx.Client, owner_headers: dict[str, str]
) -> None:
    response = gateway.get("/api/v1/vpn/tunnels", headers=owner_headers)

    assert response.status_code == 404


def test_system_status_reports_every_component(
    gateway: httpx.Client, owner_headers: dict[str, str], contract: ContractCheck
) -> None:
    response = gateway.get("/api/v1/system/status", headers=owner_headers)

    assert response.status_code == 200
    report = response.json()
    contract("SystemStatus", report)
    assert report["status"] == "ok"
    states = {
        (component.get("reported_by"), component["name"]): component["status"]
        for component in report["components"]
    }
    assert states == {
        (None, "pf-gateway"): "ok",
        (None, "core"): "ok",
        (None, "cloud"): "ok",
        (None, "ai"): "ok",
        (None, "identity-provider"): "ok",
        ("core", "postgres"): "ok",
        ("cloud", "postgres"): "ok",
    }
    dependencies = [c for c in report["components"] if c["name"] == "postgres"]
    assert {c["kind"] for c in dependencies} == {"dependency"}


def test_system_status_requires_authentication(gateway: httpx.Client) -> None:
    assert gateway.get("/api/v1/system/status").status_code == 401


def test_viewer_may_read_system_status(
    gateway: httpx.Client, viewer_headers: dict[str, str]
) -> None:
    assert gateway.get("/api/v1/system/status", headers=viewer_headers).status_code == 200
