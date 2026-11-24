#!/usr/bin/env python3
"""End-to-end check of ParallelF VPN with one gateway and one device.

    make verify-vpn

Needs the stack (`make up`), the gateway agent (`make wg-agent-install`) and
root (the device is simulated in a network namespace). Uses only the
standard library and wireguard-tools. It enrols a device with a locally
generated key, connects it, shows that an enrolled but inactive device is
dropped, activates it, checks policy enforcement, deactivates it, and
measures how long a revocation takes to reach the gateway.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vpnclient

GATEWAY = os.environ.get("PF_GATEWAY_URL", "http://localhost:8000")
KEYCLOAK = os.environ.get("PF_KEYCLOAK_URL", "http://localhost:8080")
PLATFORM = "10.255.0.1"
REVOCATION_TARGET_S = 10.0

passed = 0


def ok(message: str) -> None:
    global passed
    passed += 1
    print(f"  PASS  {message}", flush=True)


def fail(message: str) -> NoReturn:
    print(f"  FAIL  {message}", flush=True)
    print(f"\n{passed} passed, 1 failed")
    sys.exit(1)


def token() -> str:
    password = os.environ.get("PF_DEV_OWNER_PASSWORD")
    if not password:
        fail("PF_DEV_OWNER_PASSWORD is not set; run through make, which loads .env")
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "parallelf-dev-cli",
            "username": "owner",
            "password": password,
        }
    ).encode()
    with urllib.request.urlopen(
        f"{KEYCLOAK}/realms/parallelf/protocol/openid-connect/token", form, timeout=10
    ) as r:
        return str(json.load(r)["access_token"])


def call(method: str, path: str, body: Any = None) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GATEWAY + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token()}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else None


def expect(method: str, path: str, status: int, body: Any = None) -> Any:
    code, out = call(method, path, body)
    if code != status:
        fail(f"{method} {path}: expected {status}, got {code}: {out}")
    return out


def until(check: Any, timeout: float, what: str) -> float:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if check():
            return time.monotonic() - start
        time.sleep(0.2)
    fail(f"{what} within {timeout:.0f}s")


def main() -> None:
    print("Gateway")
    gateway = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and gateway is None:
        ready = [
            g for g in expect("GET", "/api/v1/vpn/gateways", 200)["items"] if g["status"] == "READY"
        ]
        gateway = ready[0] if ready else None
        if gateway is None:
            time.sleep(2)
    if gateway is None:
        fail("no READY gateway; install the agent with `make wg-agent-install`")
    ok(f"gateway {gateway['name']} is READY at {gateway['endpoint']} ({gateway['address']})")

    print("Enrolment")
    private, public = vpnclient.generate_keys()
    name = f"verify-{int(time.time()) % 100000:05d}"
    enrol = expect(
        "POST",
        "/api/v1/vpn/devices",
        201,
        {"name": name, "public_key": public, "preshared_key": True},
    )
    device, config = enrol["device"], enrol["config"]
    if private in json.dumps(enrol):
        fail("the private key must never reach the server")
    ok(
        f"enrolled {name} at {device['address']} with a pre-shared key "
        "(only the public key was sent)"
    )
    path = f"/api/v1/vpn/devices/{device['id']}"
    until(lambda: vpnclient.gateway_has_peer(public), 15, "the gateway did not add the peer")
    until(
        lambda: call("GET", path)[1]["state"] == "ENROLLED",
        15,
        "the device did not become ENROLLED",
    )
    ok("the gateway configured the peer; device ENROLLED")

    client = vpnclient.Client()
    listener = vpnclient.listen(PLATFORM, 8000)
    blocked = vpnclient.listen(PLATFORM, 9999)
    try:
        client.up(private, config, config.get("preshared_key", ""))
        until(lambda: client.handshake_age() is not None, 20, "no WireGuard handshake")
        ok("WireGuard handshake completed")
        if client.ping(PLATFORM):
            fail("an enrolled device that is not active must be dropped")
        ok("not active yet: traffic is dropped (enrolled is not allowed)")

        print("Activation")
        expect("POST", f"{path}/activate", 200, {"ttl_seconds": 600})
        elapsed = until(lambda: client.ping(PLATFORM, 1), 10, "no ping after activation")
        ok(f"activated: the platform answers ping after {elapsed:.1f}s")
        if not client.tcp(PLATFORM, 8000):
            fail("policy admins-to-platform should allow TCP 8000")
        ok("policy allows TCP 8000 on the platform")
        if client.tcp(PLATFORM, 9999):
            fail("TCP 9999 is in no policy and must be denied")
        ok("TCP 9999 is denied by default")

        expect("POST", f"{path}/deactivate", 200)
        until(lambda: not client.ping(PLATFORM, 1), 10, "still reachable after deactivation")
        ok("deactivated: traffic is dropped again")

        print("Revocation")
        expect("POST", f"{path}/activate", 200, {"ttl_seconds": 600})
        until(lambda: client.ping(PLATFORM, 1), 10, "no ping after re-activation")
        code, _ = call("DELETE", path)
        if code != 428:
            fail(f"revocation without confirmation must answer 428, got {code}")
        start = time.monotonic()
        expect("DELETE", f"{path}?confirm={name}", 200)
        until(
            lambda: not vpnclient.gateway_has_peer(public),
            REVOCATION_TARGET_S,
            "peer still on the gateway",
        )
        latency = time.monotonic() - start
        if client.ping(PLATFORM, 1):
            fail("a revoked device must not reach anything")
        ok(
            f"revoked: peer removed from the gateway {latency:.2f}s after the request "
            f"(target < {REVOCATION_TARGET_S:.0f}s)"
        )
    finally:
        client.down()
        listener.close()
        blocked.close()

    print("Audit")
    v = expect("GET", "/api/v1/vpn/audit/verify", 200)
    if not v["valid"]:
        fail(f"audit chain broken at {v.get('first_invalid_seq')}")
    ok(f"audit chain of {v['entries']} entries verifies")
    print(f"\n{passed} passed, 0 failed")


if __name__ == "__main__":
    main()
