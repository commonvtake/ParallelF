"""ParallelF NetGuard: the API contract, triage, evidence and scopes.

Contract tests always run. The sensor test needs pf-ng-sensor reporting on
this host; it is skipped without one unless ``PF_REQUIRE_NETGUARD_SENSOR=1``
(set in CI) turns that into a failure. Detections over real traffic are
covered by ``make verify-netguard``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from collections.abc import Callable
from typing import Any

import httpx
import psycopg
import pytest

ContractCheck = Callable[[str, object], None]

NG = "/api/v1/network"
REQUIRE_SENSOR = os.environ.get("PF_REQUIRE_NETGUARD_SENSOR") == "1"
KEYCLOAK_URL = os.environ.get("PF_KEYCLOAK_URL", "http://localhost:8080")


def unique(prefix: str) -> str:
    return f"{prefix}-{os.urandom(3).hex()}"


def fresh_headers(username: str = "owner") -> dict[str, str]:
    """A token from a sign-in that just happened (issuing a scope requires one)."""
    response = httpx.post(
        f"{KEYCLOAK_URL}/realms/parallelf/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "parallelf-dev-cli",
            "username": username,
            "password": os.environ[f"PF_DEV_{username.upper()}_PASSWORD"],
        },
        timeout=10,
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def netguard_db() -> psycopg.Connection[tuple[Any, ...]]:
    password = os.environ["PF_NETGUARD_DB_PASSWORD"]
    port = os.environ.get("PF_POSTGRES_HOST_PORT", "5432")
    url = f"postgresql://pf_netguard:{password}@localhost:{port}/parallelf"
    return psycopg.connect(url, autocommit=True, connect_timeout=10)


def test_network_requires_authentication(gateway: httpx.Client) -> None:
    for path in ("/overview", "/sensors", "/alerts", "/incidents", "/scopes", "/audit"):
        assert gateway.get(NG + path).status_code == 401, path


def test_read_endpoints_match_the_contract(
    gateway: httpx.Client, viewer_headers: dict[str, str], contract: ContractCheck
) -> None:
    for path, schema in (
        ("/overview", "NetworkOverview"),
        ("/sensors", "NetworkSensorList"),
        ("/alerts?limit=50", "NetworkAlertList"),
        ("/incidents", "NetworkIncidentList"),
        ("/assets", "NetworkAssetList"),
        ("/scopes", "NetworkScopeList"),
        ("/events?limit=20", "NetworkEventPage"),
    ):
        response = gateway.get(NG + path, headers=viewer_headers)
        assert response.status_code == 200, (path, response.text)
        contract(schema, response.json())
    assert gateway.get(f"{NG}/alerts?severity=urgent", headers=viewer_headers).status_code == 422
    assert gateway.get(f"{NG}/events?ip=nope", headers=viewer_headers).status_code == 422


def test_viewers_cannot_triage_or_issue_scopes(
    gateway: httpx.Client, viewer_headers: dict[str, str]
) -> None:
    created = gateway.post(
        f"{NG}/incidents",
        json={"title": "viewer incident", "severity": "low"},
        headers=viewer_headers,
    )
    assert created.status_code == 403
    scope = gateway.post(
        f"{NG}/scopes",
        json={
            "name": "viewer-scope",
            "cidrs": ["10.255.0.0/30"],
            "techniques": ["icmp-echo"],
            "authorization_note": "viewers may not do this",
        },
        headers=viewer_headers,
    )
    assert scope.status_code == 403
    assert gateway.get(f"{NG}/audit", headers=viewer_headers).status_code == 403


def test_incident_with_append_only_evidence(
    gateway: httpx.Client, owner_headers: dict[str, str], contract: ContractCheck
) -> None:
    bad = gateway.post(
        f"{NG}/incidents", json={"title": "x", "severity": "urgent"}, headers=owner_headers
    )
    assert bad.status_code == 422
    assert {e["field"] for e in bad.json()["errors"]} == {"title", "severity"}

    created = gateway.post(
        f"{NG}/incidents",
        json={"title": unique("it-incident"), "severity": "medium", "summary": "Integration test."},
        headers=owner_headers,
    )
    assert created.status_code == 201, created.text
    contract("NetworkIncident", created.json())
    incident = created.json()
    path = f"{NG}/incidents/{incident['id']}"

    note = b"Analyst note: nothing to see here."
    ev = gateway.post(
        f"{path}/evidence",
        json={"kind": "note", "name": "triage note", "content": base64.b64encode(note).decode()},
        headers=owner_headers,
    )
    assert ev.status_code == 201, ev.text
    contract("NetworkEvidence", ev.json())
    assert ev.json()["sha256"] == hashlib.sha256(note).hexdigest()

    content = gateway.get(f"{path}/evidence/{ev.json()['id']}", headers=owner_headers)
    assert content.status_code == 200
    assert content.content == note
    assert content.headers["X-Content-SHA256"] == ev.json()["sha256"]
    assert content.headers["Content-Disposition"].startswith("attachment")

    verified = gateway.get(f"{path}/verify-evidence", headers=owner_headers)
    contract("NetworkEvidenceVerification", verified.json())
    assert verified.json() == {"checked": 1, "valid": True, "mismatch": []}

    with netguard_db() as db, pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.execute(
            "UPDATE netguard.evidence SET name = 'changed' WHERE id = %s", (ev.json()["id"],)
        )

    resolved = gateway.patch(
        path, json={"status": "resolved", "note": "Closed by the test."}, headers=owner_headers
    )
    assert resolved.status_code == 200, resolved.text
    late = gateway.post(
        f"{path}/evidence",
        json={"kind": "note", "name": "late", "content": base64.b64encode(b"x").decode()},
        headers=owner_headers,
    )
    assert late.status_code == 409

    detail = gateway.get(path, headers=owner_headers)
    contract("NetworkIncidentDetail", detail.json())
    kinds = [t["kind"] for t in detail.json()["timeline"]]
    assert kinds[0] == "opened" and "evidence" in kinds and "status" in kinds and "note" in kinds

    with netguard_db() as db:
        subjects = [
            r[0]
            for r in db.execute(
                "SELECT subject FROM netguard.outbox WHERE headers->>'ce-subject' = %s"
                " ORDER BY created_at",
                (f"incident/{incident['id']}",),
            ).fetchall()
        ]
    assert subjects == [
        "pf.netguard.evt.incident.changed",
        "pf.netguard.evt.evidence.added",
        "pf.netguard.evt.incident.changed",
    ]


def test_discovery_scopes(
    gateway: httpx.Client, owner_headers: dict[str, str], contract: ContractCheck
) -> None:
    outside = gateway.post(
        f"{NG}/scopes",
        json={
            "name": "home-lan",
            "cidrs": ["192.168.1.0/24"],
            "techniques": ["icmp-echo"],
            "authorization_note": "Not a ParallelF network.",
        },
        headers=fresh_headers(),
    )
    assert outside.status_code == 422
    assert outside.json()["errors"][0]["code"] == "not_owned"

    syn = gateway.post(
        f"{NG}/scopes",
        json={
            "name": "syn-scan",
            "cidrs": ["10.255.0.0/30"],
            "techniques": ["tcp-syn"],
            "authorization_note": "A technique NetGuard never runs.",
        },
        headers=fresh_headers(),
    )
    assert syn.status_code == 422

    name = unique("it-scope")
    created = gateway.post(
        f"{NG}/scopes",
        json={
            "name": name,
            "cidrs": ["10.255.3.252/30"],
            "techniques": ["icmp-echo"],
            "duration": "2m",
            "rate_pps": 5,
            "authorization_note": "Integration test of scope issuing.",
        },
        headers=fresh_headers(),
    )
    assert created.status_code == 201, created.text
    contract("NetworkScope", created.json())
    scope = created.json()
    assert scope["status"] == "active"
    path = f"{NG}/scopes/{scope['id']}"
    assert gateway.delete(path, headers=owner_headers).status_code == 428
    revoked = gateway.delete(f"{path}?confirm={name}", headers=owner_headers)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert gateway.delete(f"{path}?confirm={name}", headers=owner_headers).status_code == 409

    page = gateway.get(f"{NG}/audit?resource_id={scope['id']}", headers=owner_headers)
    contract("AuditPage", page.json())
    assert [e["action"] for e in page.json()["items"]] == [
        "network.scopes.revoke",
        "network.scopes.issue",
    ]
    verified = gateway.get(f"{NG}/audit/verify", headers=owner_headers).json()
    assert verified["valid"] is True


def test_sensor_reports_on_the_vpn_interface(
    gateway: httpx.Client, owner_headers: dict[str, str]
) -> None:
    deadline = time.monotonic() + (90 if REQUIRE_SENSOR else 5)
    sensors: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        sensors = [
            s
            for s in gateway.get(f"{NG}/sensors", headers=owner_headers).json()["items"]
            if s["status"] == "reporting"
        ]
        if sensors:
            break
        time.sleep(2)
    if not sensors:
        if REQUIRE_SENSOR:
            pytest.fail("no reporting sensor; install it with `make ng-sensor-install`")
        pytest.skip("no reporting sensor on this host")
    sensor = sensors[0]
    assert sensor["engine"].startswith("Suricata"), sensor
    assert sensor["engine_error"] == "", sensor
    assert "wg-pf0" in sensor["interfaces"], sensor
