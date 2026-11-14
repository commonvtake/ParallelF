#!/usr/bin/env python3
"""End-to-end check of ParallelF Cloud on one host with one VM.

    make verify-cloud

Needs the stack (`make up`) and a running node agent (`make agent` or
`make agent-install`). Uses only the Python standard library. It creates a
project, a NAT network and a CirrOS VM, waits for the VM to run, pings it
from the host, checks metrics, stops and starts it, deletes everything
again (proving the delete confirmation), and verifies the audit chain.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

GATEWAY = os.environ.get("PF_GATEWAY_URL", "http://localhost:8000")
KEYCLOAK = os.environ.get("PF_KEYCLOAK_URL", "http://localhost:8080")
TEMPLATE = os.environ.get("PF_VERIFY_TEMPLATE", "cirros")

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


class API:
    def __init__(self) -> None:
        self.token = token()
        self.issued = time.monotonic()

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        if time.monotonic() - self.issued > 240:  # tokens live five minutes
            self.token, self.issued = token(), time.monotonic()
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(GATEWAY + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, json.loads(raw) if raw else None

    def expect(self, method: str, path: str, status: int, body: Any = None) -> Any:
        code, out = self.call(method, path, body)
        if code != status:
            fail(f"{method} {path}: expected {status}, got {code}: {out}")
        return out


def wait_for(api: API, workload_id: str, state: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        w = api.expect("GET", f"/api/v1/cloud/workloads/{workload_id}", 200)
        progress = f"{w['state']} {w['status_message']}".strip()
        if progress != last:
            print(f"        {progress}", flush=True)
            last = progress
        if w["state"] == state:
            return dict(w)
        if w["state"] == "ERROR":
            fail(f"workload failed: {w['status_message']}")
        time.sleep(2)
    fail(f"workload did not reach {state} within {timeout:.0f}s (last: {last})")


def main() -> None:
    api = API()
    print("Compute node")
    deadline = time.monotonic() + 90
    node = None
    while time.monotonic() < deadline:
        nodes = api.expect("GET", "/api/v1/cloud/nodes", 200)["items"]
        ready = [n for n in nodes if n["status"] == "READY" and n["kvm"]]
        if ready:
            node = ready[0]
            break
        time.sleep(3)
    if node is None:
        fail("no READY node with KVM; start the agent with `make agent`")
    ok(f"node {node['name']} is READY ({node['hypervisor']})")
    alloc = node["allocatable"]
    ok(f"allocatable: {alloc['vcpus']} vCPUs, {alloc['memory_mib']} MiB, {alloc['disk_gib']} GiB")

    suffix = f"{int(time.time()) % 100000:05d}"
    project = api.expect(
        "POST",
        "/api/v1/core/projects",
        201,
        {"slug": f"cloud-check-{suffix}", "name": "Cloud check"},
    )
    try:
        run(api, project["id"], suffix)
    finally:
        api.call("DELETE", f"/api/v1/core/projects/{project['id']}")

    print("Audit")
    verification = api.expect("GET", "/api/v1/cloud/audit/verify", 200)
    if not verification["valid"]:
        fail(f"audit chain broken at entry {verification.get('first_invalid_seq')}")
    ok(f"audit chain of {verification['entries']} entries verifies")
    print(f"\n{passed} passed, 0 failed")


def host_networks() -> list[ipaddress.IPv4Network]:
    """This host's route destinations: libvirt refuses networks that overlap one."""
    out = []
    for line in Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[1] != "00000000":
            dest = socket.inet_ntoa(struct.pack("<I", int(fields[1], 16)))
            mask = socket.inet_ntoa(struct.pack("<I", int(fields[7], 16)))
            out.append(ipaddress.IPv4Network(f"{dest}/{mask}", strict=False))
    return out


def free_cidr() -> str:
    taken = host_networks()
    for _ in range(200):
        net = ipaddress.IPv4Network(f"10.{random.randint(100, 254)}.{random.randint(0, 255)}.0/24")
        if not any(net.overlaps(t) for t in taken):
            return str(net)
    fail("no CIDR free of host routes")


def run(api: API, project_id: str, suffix: str) -> None:
    print("Network")
    network = None
    for _ in range(10):
        cidr = free_cidr()
        code, out = api.call(
            "POST",
            "/api/v1/cloud/networks",
            {"project_id": project_id, "name": f"check-net-{suffix}", "kind": "nat", "cidr": cidr},
        )
        if code == 201:
            network = out
            break
        if code != 409:
            fail(f"create network: {code} {out}")
    if network is None:
        fail("no free CIDR found")
    ok(f"network {network['name']} {network['cidr']} (gateway {network['gateway_ip']})")

    print(f"Virtual machine ({TEMPLATE})")
    vm = api.expect(
        "POST",
        "/api/v1/cloud/workloads",
        201,
        {
            "project_id": project_id,
            "name": f"check-vm-{suffix}",
            "template": TEMPLATE,
            "network_id": network["id"],
        },
    )
    ok(f"admitted {vm['name']} with address {vm['ip']} and MAC {vm['mac']}")
    started = time.monotonic()
    vm = wait_for(api, vm["id"], "RUNNING", 300)
    elapsed = time.monotonic() - started
    ok(f"RUNNING on {vm['node']} after {elapsed:.0f}s (generation {vm['generation']})")

    ipaddress.ip_address(vm["ip"])
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if (
            subprocess.run(["ping", "-c", "1", "-W", "1", vm["ip"]], capture_output=True).returncode
            == 0
        ):
            ok(f"the host reaches the VM at {vm['ip']} (DHCP reservation honoured)")
            break
        time.sleep(2)
    else:
        fail(f"no reply from {vm['ip']} within 120s")

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        points = api.expect("GET", f"/api/v1/cloud/workloads/{vm['id']}/metrics?window=15m", 200)[
            "points"
        ]
        if points:
            p = points[-1]
            ok(f"metrics reported: {p['cpu_percent']:.1f}% CPU, {p['memory_used_mib']} MiB")
            break
        time.sleep(3)
    else:
        fail("no workload metrics within 60s")

    print("Lifecycle")
    api.expect("POST", f"/api/v1/cloud/workloads/{vm['id']}/stop", 202)
    wait_for(api, vm["id"], "STOPPED", 150)
    ok("stopped (ACPI shutdown)")
    api.expect("POST", f"/api/v1/cloud/workloads/{vm['id']}/start", 202)
    wait_for(api, vm["id"], "RUNNING", 120)
    ok("started again")

    code, _ = api.call("DELETE", f"/api/v1/cloud/workloads/{vm['id']}")
    if code != 428:
        fail(f"delete without confirmation must answer 428, got {code}")
    ok("delete without the name is refused (428)")
    api.expect("DELETE", f"/api/v1/cloud/workloads/{vm['id']}?confirm={vm['name']}", 202)
    wait_for(api, vm["id"], "DELETED", 120)
    ok("deleted; address released")

    api.expect("DELETE", f"/api/v1/cloud/networks/{network['id']}?confirm={network['name']}", 204)
    ok("network deleted")


if __name__ == "__main__":
    main()
