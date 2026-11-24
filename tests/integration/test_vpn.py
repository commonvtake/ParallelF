"""ParallelF VPN: the API contract and a real WireGuard gateway.

Contract tests always run. Gateway tests need a READY gateway agent on this
host and root (or passwordless sudo): a network namespace plays the user's
device. They are skipped without a gateway unless ``PF_REQUIRE_VPN_GATEWAY=1``
(set in CI) turns that into a failure. ``PF_CLOUD_DISRUPTIVE_TESTS=1`` adds
the fail-closed test, which stops pf-vpnd.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "dev"))
import vpnclient  # noqa: E402

ContractCheck = Callable[[str, object], None]

VPN = "/api/v1/vpn"
PLATFORM = "10.255.0.1"
REQUIRE_GATEWAY = os.environ.get("PF_REQUIRE_VPN_GATEWAY") == "1"
DISRUPTIVE = os.environ.get("PF_CLOUD_DISRUPTIVE_TESTS") == "1"
KEYCLOAK_URL = os.environ.get("PF_KEYCLOAK_URL", "http://localhost:8080")


def fresh_headers(username: str = "owner") -> dict[str, str]:
    """A token from a sign-in that just happened (activation requires one)."""
    password = os.environ[f"PF_DEV_{username.upper()}_PASSWORD"]
    response = httpx.post(
        f"{KEYCLOAK_URL}/realms/parallelf/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "parallelf-dev-cli",
            "username": username,
            "password": password,
        },
        timeout=10,
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def until(check: Callable[[], bool], timeout: float, what: str) -> float:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if check():
            return time.monotonic() - start
        time.sleep(0.25)
    pytest.fail(f"{what} within {timeout:.0f}s")


class Devices:
    """Enrols devices and revokes whatever is left after a test."""

    def __init__(self, gateway: httpx.Client) -> None:
        self.gateway = gateway
        self.created: list[dict[str, Any]] = []

    def enrol(self, name: str, public_key: str, **extra: Any) -> dict[str, Any]:
        response = self.gateway.post(
            f"{VPN}/devices",
            json={"name": name, "public_key": public_key, **extra},
            headers=fresh_headers(),
        )
        assert response.status_code == 201, response.text
        body: dict[str, Any] = response.json()
        self.created.append(body["device"])
        return body

    def cleanup(self) -> None:
        for d in self.created:
            self.gateway.delete(
                f"{VPN}/devices/{d['id']}?confirm={d['name']}", headers=fresh_headers()
            )


@pytest.fixture
def devices(gateway: httpx.Client) -> Iterator[Devices]:
    d = Devices(gateway)
    yield d
    d.cleanup()


def unique(prefix: str) -> str:
    return f"{prefix}-{os.urandom(3).hex()}"


# --- Contract ---------------------------------------------------------------


def test_vpn_requires_authentication(gateway: httpx.Client) -> None:
    for path in ("/gateways", "/devices", "/policies", "/audit"):
        assert gateway.get(VPN + path).status_code == 401, path


def test_policies_and_permissions(
    gateway: httpx.Client,
    owner_headers: dict[str, str],
    viewer_headers: dict[str, str],
    contract: ContractCheck,
) -> None:
    listed = gateway.get(f"{VPN}/policies", headers=viewer_headers)
    assert listed.status_code == 200
    contract("VPNPolicyList", listed.json())
    names = {p["name"] for p in listed.json()["items"]}
    assert {"admins-to-platform", "ping-platform"} <= names

    key = vpnclient.generate_keys()[1]
    denied = gateway.post(
        f"{VPN}/devices", json={"name": "viewer-phone", "public_key": key}, headers=viewer_headers
    )
    assert denied.status_code == 403
    assert gateway.get(f"{VPN}/audit", headers=viewer_headers).status_code == 403
    assert gateway.get(f"{VPN}/devices?scope=all", headers=viewer_headers).status_code == 403

    bad = gateway.post(
        f"{VPN}/policies",
        json={
            "name": "into-tunnel",
            "priority": 50,
            "action": "allow",
            "groups": ["owner"],
            "destinations": ["10.255.0.0/24"],
            "protocol": "icmp",
            "ports": ["22"],
        },
        headers=owner_headers,
    )
    assert bad.status_code == 422
    assert {e["field"] for e in bad.json()["errors"]} == {"destinations", "ports"}

    name = unique("it-policy")
    created = gateway.post(
        f"{VPN}/policies",
        json={
            "name": name,
            "priority": 500,
            "action": "deny",
            "groups": ["viewer"],
            "destinations": ["10.20.0.0/16"],
            "protocol": "tcp",
            "ports": ["22", "8000-8100"],
        },
        headers=owner_headers,
    )
    assert created.status_code == 201, created.text
    contract("VPNPolicy", created.json())
    policy_id = created.json()["id"]
    path = f"{VPN}/policies/{policy_id}"
    assert gateway.delete(path, headers=owner_headers).status_code == 428
    assert gateway.delete(f"{path}?confirm={name}", headers=owner_headers).status_code == 204

    page = gateway.get(f"{VPN}/audit?resource_id={policy_id}", headers=owner_headers)
    contract("AuditPage", page.json())
    assert [e["action"] for e in page.json()["items"]] == [
        "vpn.policies.delete",
        "vpn.policies.create",
    ]
    verified = gateway.get(f"{VPN}/audit/verify", headers=owner_headers).json()
    contract("AuditVerification", verified)
    assert verified["valid"] is True


def test_enrolment_validation(gateway: httpx.Client, owner_headers: dict[str, str]) -> None:
    response = gateway.post(
        f"{VPN}/devices",
        json={"name": "Not Valid", "public_key": "not-a-key"},
        headers=owner_headers,
    )
    assert response.status_code == 422
    assert {e["field"] for e in response.json()["errors"]} == {"name", "public_key"}


# --- With a gateway -------------------------------------------------------------


@pytest.fixture
def ready_gateway(gateway: httpx.Client, owner_headers: dict[str, str]) -> dict[str, Any]:
    deadline = time.monotonic() + (60 if REQUIRE_GATEWAY else 3)
    while True:
        items = gateway.get(f"{VPN}/gateways", headers=owner_headers).json()["items"]
        ready = [g for g in items if g["status"] == "READY"]
        if ready:
            found: dict[str, Any] = ready[0]
            return found
        if time.monotonic() > deadline:
            break
        time.sleep(2)
    if REQUIRE_GATEWAY:
        pytest.fail("PF_REQUIRE_VPN_GATEWAY=1 but no gateway is READY")
    pytest.skip("no READY VPN gateway; install one with `make wg-agent-install`")


@pytest.fixture
def client() -> Iterator[vpnclient.Client]:
    c = vpnclient.Client()
    yield c
    c.down()


@pytest.fixture
def services() -> Iterator[None]:
    """Listeners on the gateway's tunnel address: 8000 is in a policy, 9999 is not."""
    sockets = [vpnclient.listen(PLATFORM, 8000), vpnclient.listen(PLATFORM, 9999)]
    yield
    for s in sockets:
        s.close()


def test_device_lifecycle_on_a_real_gateway(
    gateway: httpx.Client,
    ready_gateway: dict[str, Any],
    devices: Devices,
    client: vpnclient.Client,
    services: None,
    contract: ContractCheck,
) -> None:
    contract("VPNGateway", ready_gateway)
    private, public = vpnclient.generate_keys()
    name = unique("it-laptop")
    enrolment = devices.enrol(name, public, preshared_key=True)
    contract("VPNEnrolment", enrolment)
    device, config = enrolment["device"], enrolment["config"]
    assert private not in json.dumps(enrolment)
    assert device["state"] == "PENDING" and device["active"] is False
    assert device["groups"] == ["owner"]
    assert config["gateway_public_key"] == ready_gateway["public_key"]
    assert config["allowed_ips"][0] == "10.255.0.0/22"
    psk = config["preshared_key"]
    path = f"{VPN}/devices/{device['id']}"

    until(lambda: vpnclient.gateway_has_peer(public), 15, "the gateway did not add the peer")
    until(
        lambda: gateway.get(path, headers=fresh_headers()).json()["state"] == "ENROLLED",
        15,
        "the device did not become ENROLLED",
    )
    # The pre-shared key reached the gateway and is not shown again.
    assert "preshared_key" not in gateway.get(f"{path}/config", headers=fresh_headers()).json()

    client.up(private, config, psk)
    until(lambda: client.handshake_age() is not None, 20, "no WireGuard handshake")
    assert not client.ping(PLATFORM), "enrolled is not allowed: an inactive device is dropped"

    activated = gateway.post(f"{path}/activate", json={"ttl_seconds": 600}, headers=fresh_headers())
    assert activated.status_code == 200, activated.text
    contract("VPNDevice", activated.json())
    assert activated.json()["active"] is True
    until(lambda: client.ping(PLATFORM, 1), 10, "no ping after activation")
    assert client.tcp(PLATFORM, 8000), "admins-to-platform allows TCP 8000"
    assert not client.tcp(PLATFORM, 9999), "TCP 9999 is in no policy"

    # A policy change reaches the gateway without touching the activation.
    policy = unique("it-allow")
    created = gateway.post(
        f"{VPN}/policies",
        json={
            "name": policy,
            "priority": 50,
            "action": "allow",
            "groups": ["owner"],
            "destinations": ["platform"],
            "protocol": "tcp",
            "ports": ["9999"],
        },
        headers=fresh_headers(),
    )
    assert created.status_code == 201, created.text
    try:
        until(lambda: client.tcp(PLATFORM, 9999, 1), 10, "the new policy was not applied")
    finally:
        gateway.delete(
            f"{VPN}/policies/{created.json()['id']}?confirm={policy}", headers=fresh_headers()
        )
    until(lambda: not client.tcp(PLATFORM, 9999, 1), 10, "the deleted policy still applies")
    assert client.ping(PLATFORM, 1), "the activation survived the policy change"

    stats = gateway.get(path, headers=fresh_headers()).json()
    assert stats["connection"] == "online" and stats["rx_bytes"] > 0

    deactivated = gateway.post(f"{path}/deactivate", headers=fresh_headers())
    assert deactivated.status_code == 200 and deactivated.json()["active"] is False
    until(lambda: not client.ping(PLATFORM, 1), 10, "still reachable after deactivation")

    # Revocation: the gateway drops the peer within the target.
    assert gateway.post(f"{path}/activate", headers=fresh_headers()).status_code == 200
    until(lambda: client.ping(PLATFORM, 1), 10, "no ping after re-activation")
    assert gateway.delete(path, headers=fresh_headers()).status_code == 428
    start = time.monotonic()
    revoked = gateway.delete(f"{path}?confirm={name}", headers=fresh_headers())
    assert revoked.status_code == 200 and revoked.json()["state"] == "REVOKED"
    until(lambda: not vpnclient.gateway_has_peer(public), 10, "the revoked peer is still there")
    latency = time.monotonic() - start
    assert latency < 10, f"revocation took {latency:.1f}s"
    assert not client.ping(PLATFORM, 1)

    actions = [
        e["action"]
        for e in gateway.get(
            f"{VPN}/audit?resource_id={device['id']}", headers=fresh_headers()
        ).json()["items"]
    ]
    assert actions[::-1] == [
        "vpn.devices.create",
        "vpn.devices.activate",
        "vpn.devices.deactivate",
        "vpn.devices.activate",
        "vpn.devices.revoke",
    ]


def test_another_users_device_is_invisible(
    gateway: httpx.Client, ready_gateway: dict[str, Any], devices: Devices
) -> None:
    public = vpnclient.generate_keys()[1]
    device = devices.enrol(unique("it-private"), public)["device"]
    # A viewer cannot see it, a manager can.
    viewer = gateway.get(f"{VPN}/devices/{device['id']}", headers=fresh_headers("viewer"))
    assert viewer.status_code == 404
    everything = gateway.get(f"{VPN}/devices?scope=all", headers=fresh_headers()).json()["items"]
    assert device["id"] in {d["id"] for d in everything}


@pytest.mark.skipif(not DISRUPTIVE, reason="set PF_CLOUD_DISRUPTIVE_TESTS=1 (stops pf-vpnd)")
def test_activation_expires_even_without_the_control_plane(
    gateway: httpx.Client,
    ready_gateway: dict[str, Any],
    devices: Devices,
    client: vpnclient.Client,
    services: None,
) -> None:
    private, public = vpnclient.generate_keys()
    enrolment = devices.enrol(unique("it-failclosed"), public)
    path = f"{VPN}/devices/{enrolment['device']['id']}"
    until(lambda: vpnclient.gateway_has_peer(public), 15, "the gateway did not add the peer")
    client.up(private, enrolment["config"])
    activated = gateway.post(f"{path}/activate", json={"ttl_seconds": 30}, headers=fresh_headers())
    assert activated.status_code == 200, activated.text
    until(lambda: client.ping(PLATFORM, 1), 10, "no ping after activation")

    compose = [
        "docker",
        "compose",
        "--env-file",
        str(REPO_ROOT / ".env"),
        "-f",
        str(REPO_ROOT / "deploy" / "compose" / "compose.yaml"),
    ]
    subprocess.run([*compose, "stop", "vpn"], check=True, capture_output=True, timeout=120)
    try:
        # The control plane is gone; the kernel ends the activation on time.
        elapsed = until(lambda: not client.ping(PLATFORM, 1), 45, "access outlived its expiry")
        assert elapsed < 40
    finally:
        subprocess.run([*compose, "start", "vpn"], check=True, capture_output=True, timeout=120)
    until(
        lambda: gateway.get(f"{VPN}/gateways", headers=fresh_headers()).status_code == 200,
        90,
        "pf-vpnd did not come back",
    )


def test_device_events_are_written_to_the_outbox(
    gateway: httpx.Client, ready_gateway: dict[str, Any], devices: Devices
) -> None:
    public = vpnclient.generate_keys()[1]
    device = devices.enrol(unique("it-events"), public)["device"]
    password = os.environ["PF_VPN_DB_PASSWORD"]
    port = os.environ.get("PF_POSTGRES_HOST_PORT", "5432")
    url = f"postgresql://pf_vpn:{password}@localhost:{port}/parallelf"
    with psycopg.connect(url, autocommit=True, connect_timeout=10) as db:
        rows = db.execute(
            "SELECT subject, convert_from(payload, 'UTF8') FROM vpn.outbox"
            " WHERE headers->>'ce-subject' = %s ORDER BY created_at",
            (f"device/{device['id']}",),
        ).fetchall()
    assert rows[0][0] == "pf.vpn.evt.device.created"
    created = json.loads(rows[0][1])
    # NetGuard attributes tunnel traffic with this: address -> owner.
    assert created["address"] == device["address"]
    assert created["ownerSubject"] == device["owner_subject"]
