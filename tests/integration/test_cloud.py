"""ParallelF Cloud: the API contract, admission rules and real workloads.

Three tiers, selected by the environment:

* Contract tests always run. They need the stack only; no compute node.
* Runtime tests boot real VMs and containers. They run when a READY node is
  registered, and are skipped otherwise, unless ``PF_REQUIRE_CLOUD_NODE=1``
  turns a missing node into a failure (CI sets it).
* Disruptive tests (``PF_CLOUD_DISRUPTIVE_TESTS=1``) stop and start the node
  agent and pf-cloudd, and write a broken template into the catalogue. They
  need passwordless sudo, Docker and ``PF_TEST_ADMIN_DATABASE_URL``.

Every test creates its own project, networks and workloads and deletes them
again, so the tests can run against a stack that is in use.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import secrets
import socket
import struct
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest

ContractCheck = Callable[[str, object], None]
ProjectFactory = Callable[..., dict[str, Any]]

CLOUD = "/api/v1/cloud"
REPO_ROOT = Path(__file__).resolve().parents[2]
KEYCLOAK_URL = os.environ.get("PF_KEYCLOAK_URL", "http://localhost:8080")
TOKEN_URL = f"{KEYCLOAK_URL}/realms/parallelf/protocol/openid-connect/token"
AGENT_DATA_DIR = Path(os.environ.get("PF_AGENT_DATA_DIR", "/var/lib/parallelf/cloud"))

REQUIRE_NODE = os.environ.get("PF_REQUIRE_CLOUD_NODE") == "1"
DISRUPTIVE = os.environ.get("PF_CLOUD_DISRUPTIVE_TESTS") == "1"

# What the catalogue migration (0002) must provide.
FLAVORS = {"pf.nano", "pf.micro", "pf.small", "pf.medium"}
TEMPLATES = {"cirros", "ubuntu-24.04", "alpine-sleeper", "nginx"}


# --- Helpers ---------------------------------------------------------------


class Cloud:
    """An API client for long tests: it renews its token before it expires.

    The session-scoped token fixtures live five minutes, which is shorter
    than a run of the runtime tests.
    """

    def __init__(self, gateway: httpx.Client, username: str, password: str) -> None:
        self.gateway = gateway
        self.username = username
        self.password = password
        self.token = ""
        self.issued = 0.0

    def _headers(self) -> dict[str, str]:
        if time.monotonic() - self.issued > 200:
            response = httpx.post(
                TOKEN_URL,
                data={
                    "grant_type": "password",
                    "client_id": "parallelf-dev-cli",
                    "username": self.username,
                    "password": self.password,
                },
                timeout=10,
            )
            assert response.status_code == 200, response.text
            self.token = response.json()["access_token"]
            self.issued = time.monotonic()
        return {"Authorization": f"Bearer {self.token}"}

    def request(self, method: str, path: str, body: Any = None) -> httpx.Response:
        return self.gateway.request(method, path, json=body, headers=self._headers(), timeout=20)

    def get(self, path: str) -> Any:
        response = self.request("GET", path)
        assert response.status_code == 200, f"GET {path}: {response.status_code} {response.text}"
        return response.json()

    def workload(self, workload_id: str) -> dict[str, Any]:
        body: dict[str, Any] = self.get(f"{CLOUD}/workloads/{workload_id}")
        return body

    def wait_for(
        self,
        workload_id: str,
        state: str,
        timeout: float,
        *,
        allow_error: bool = False,
    ) -> dict[str, Any]:
        """Poll a workload until it reaches state; fail on an unexpected ERROR."""
        deadline = time.monotonic() + timeout
        workload = self.workload(workload_id)
        while time.monotonic() < deadline:
            workload = self.workload(workload_id)
            if workload["state"] == state:
                return workload
            if workload["state"] == "ERROR" and not allow_error:
                pytest.fail(f"workload {workload['name']} failed: {workload['status_message']}")
            time.sleep(2)
        pytest.fail(
            f"workload {workload['name']} did not reach {state} within {timeout:.0f}s; "
            f"it is {workload['state']}: {workload['status_message']}"
        )

    def node(self, node_id: str) -> dict[str, Any]:
        body: dict[str, Any] = self.get(f"{CLOUD}/nodes/{node_id}")
        return body


def _host_networks() -> list[ipaddress.IPv4Network]:
    """The IPv4 destinations of this host's routes, to keep test CIDRs clear.

    libvirt refuses to start a network that overlaps a route (on CI runners
    the uplink itself is in 10.0.0.0/8).
    """
    out: list[ipaddress.IPv4Network] = []
    try:
        lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        dest = socket.inet_ntoa(struct.pack("<I", int(fields[1], 16)))
        mask = socket.inet_ntoa(struct.pack("<I", int(fields[7], 16)))
        if dest != "0.0.0.0":
            out.append(ipaddress.IPv4Network(f"{dest}/{mask}", strict=False))
    return out


def _free_cidr(prefix: int = 24) -> str:
    taken = _host_networks()
    for _ in range(200):
        candidate = ipaddress.IPv4Network(
            f"10.{random.randint(100, 254)}.{random.randint(0, 255)}.0/{prefix}", strict=False
        )
        if not any(candidate.overlaps(net) for net in taken):
            return str(candidate)
    pytest.fail("no CIDR free of host routes")


def _run(*argv: str, sudo: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = ["sudo", "-n", *argv] if sudo else list(argv)
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if check and result.returncode != 0:
        pytest.fail(f"{' '.join(command)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result


def _exists(path: Path) -> bool:
    """Whether a path exists; the agent's data directory is root-only."""
    return _run("test", "-e", str(path), sudo=True, check=False).returncode == 0


def _domain_exists(workload_id: str) -> bool:
    virsh = ("virsh", "-c", "qemu:///system", "dominfo", f"pf-{workload_id}")
    return _run(*virsh, sudo=True, check=False).returncode == 0


def _pings(address: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", address], capture_output=True, check=False
        )
        if result.returncode == 0:
            return True
        time.sleep(1)
    return False


class Resources:
    """Creates networks and workloads, and removes them after the test."""

    def __init__(self, cloud: Cloud, project_id: str) -> None:
        self.cloud = cloud
        self.project_id = project_id
        self.networks: list[dict[str, Any]] = []
        self.workloads: list[dict[str, Any]] = []

    def network(self, kind: str = "nat", **overrides: Any) -> dict[str, Any]:
        for attempt in range(10):
            body = {
                "project_id": self.project_id,
                "name": f"it-{kind}-{secrets.token_hex(3)}",
                "kind": kind,
                "cidr": _free_cidr(),
                **overrides,
            }
            response = self.cloud.request("POST", f"{CLOUD}/networks", body)
            if response.status_code == 409 and "cidr" not in overrides and attempt < 9:
                continue  # another network already uses this range
            assert response.status_code == 201, response.text
            network: dict[str, Any] = response.json()
            self.networks.append(network)
            return network
        pytest.fail("could not create a network")

    def workload(self, network: dict[str, Any], template: str, **overrides: Any) -> dict[str, Any]:
        body = {
            "project_id": self.project_id,
            "name": f"it-{template.split('-')[0].split('.')[0]}-{secrets.token_hex(3)}",
            "template": template,
            "network_id": network["id"],
            **overrides,
        }
        response = self.cloud.request("POST", f"{CLOUD}/workloads", body)
        assert response.status_code == 201, response.text
        workload: dict[str, Any] = response.json()
        self.workloads.append(workload)
        return workload

    def delete_workload(self, workload: dict[str, Any], timeout: float = 150) -> None:
        response = self.cloud.request(
            "DELETE", f"{CLOUD}/workloads/{workload['id']}?confirm={workload['name']}"
        )
        assert response.status_code in (202, 404, 409), response.text
        self.cloud.wait_for(workload["id"], "DELETED", timeout, allow_error=True)

    def cleanup(self) -> None:
        for workload in reversed(self.workloads):
            current = self.cloud.workload(workload["id"])
            if current["state"] != "DELETED":
                self.delete_workload(current)
        for network in reversed(self.networks):
            self.cloud.request(
                "DELETE", f"{CLOUD}/networks/{network['id']}?confirm={network['name']}"
            )


@pytest.fixture
def owner_cloud(gateway: httpx.Client) -> Cloud:
    return Cloud(gateway, "owner", os.environ["PF_DEV_OWNER_PASSWORD"])


@pytest.fixture
def project(make_project: ProjectFactory) -> dict[str, Any]:
    return make_project(name="Cloud integration test")


@pytest.fixture
def resources(owner_cloud: Cloud, project: dict[str, Any]) -> Iterator[Resources]:
    created = Resources(owner_cloud, project["id"])
    yield created
    created.cleanup()


@pytest.fixture
def cloud_db() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """A connection as pf-cloudd's runtime role."""
    password = os.environ.get("PF_CLOUD_DB_PASSWORD", "")
    if not password:
        pytest.fail("PF_CLOUD_DB_PASSWORD is not set; run `make test-integration`")
    port = os.environ.get("PF_POSTGRES_HOST_PORT", "5432")
    url = f"postgresql://pf_cloud:{password}@localhost:{port}/parallelf"
    with psycopg.connect(url, autocommit=True, connect_timeout=10) as connection:
        yield connection


@pytest.fixture
def ready_node(owner_cloud: Cloud) -> dict[str, Any]:
    """A READY compute node with KVM and Docker, or a skip (a failure in CI)."""
    deadline = time.monotonic() + (90 if REQUIRE_NODE else 5)
    while True:
        nodes = owner_cloud.get(f"{CLOUD}/nodes")["items"]
        ready = [n for n in nodes if n["status"] == "READY" and n["schedulable"]]
        if ready:
            node: dict[str, Any] = ready[0]
            return node
        if time.monotonic() > deadline:
            break
        time.sleep(3)
    if REQUIRE_NODE:
        pytest.fail("PF_REQUIRE_CLOUD_NODE=1 but no compute node is READY")
    pytest.skip("no READY compute node; start one with `make agent`")


# --- Contract and admission (no compute node needed) -------------------------


def test_cloud_api_requires_authentication(gateway: httpx.Client) -> None:
    for path in ("/nodes", "/workloads", "/networks", "/templates", "/audit"):
        assert gateway.get(CLOUD + path).status_code == 401, path


def test_catalogue_matches_the_contract(owner_cloud: Cloud, contract: ContractCheck) -> None:
    flavors = owner_cloud.get(f"{CLOUD}/flavors")
    contract("FlavorList", flavors)
    assert {f["name"] for f in flavors["items"]} >= FLAVORS

    templates = owner_cloud.get(f"{CLOUD}/templates")
    contract("TemplateList", templates)
    by_name = {t["name"]: t for t in templates["items"]}
    assert set(by_name) >= TEMPLATES

    for template in templates["items"]:
        image = template["image"]
        if template["kind"] == "vm":
            # Reproducible provisioning: VM images are fetched over https
            # and verified against a pinned digest before first use.
            assert image["source"].startswith("https://"), image
            assert len(image["sha256"]) == 64, image
        else:
            assert "@sha256:" in image["source"], f"container image is not pinned: {image}"

    assert by_name["ubuntu-24.04"]["static_network"] is True
    assert by_name["cirros"]["static_network"] is False
    assert by_name["alpine-sleeper"]["kind"] == "container"


def test_viewer_may_read_but_not_change(
    gateway: httpx.Client,
    viewer_headers: dict[str, str],
    project: dict[str, Any],
) -> None:
    for path in ("/nodes", "/workloads", "/networks", "/flavors", "/templates"):
        assert gateway.get(CLOUD + path, headers=viewer_headers).status_code == 200, path
    assert gateway.get(f"{CLOUD}/quotas/{project['id']}", headers=viewer_headers).status_code == 200

    network = {
        "project_id": project["id"],
        "name": "viewer-net",
        "kind": "nat",
        "cidr": _free_cidr(),
    }
    denied = gateway.post(f"{CLOUD}/networks", json=network, headers=viewer_headers)
    assert denied.status_code == 403
    assert denied.headers["content-type"] == "application/problem+json"

    quota = {"max_vcpus": 1, "max_memory_mib": 1, "max_disk_gib": 1, "max_workloads": 1}
    assert (
        gateway.put(
            f"{CLOUD}/quotas/{project['id']}", json=quota, headers=viewer_headers
        ).status_code
        == 403
    )
    # The audit trail is for owners, admins and analysts.
    assert gateway.get(f"{CLOUD}/audit", headers=viewer_headers).status_code == 403


def test_network_rules_and_confirmed_deletion(
    owner_cloud: Cloud,
    resources: Resources,
    contract: ContractCheck,
) -> None:
    project_id = resources.project_id

    invalid = owner_cloud.request(
        "POST",
        f"{CLOUD}/networks",
        {"project_id": project_id, "name": "public", "kind": "nat", "cidr": "192.168.1.0/24"},
    )
    assert invalid.status_code == 422
    assert {e["field"] for e in invalid.json()["errors"]} == {"cidr"}

    unknown_project = owner_cloud.request(
        "POST",
        f"{CLOUD}/networks",
        {
            "project_id": "01900000-0000-7000-8000-0000000000ff",
            "name": "orphan",
            "kind": "nat",
            "cidr": _free_cidr(),
        },
    )
    assert unknown_project.status_code == 422
    assert unknown_project.json()["errors"][0]["field"] == "project_id"

    nat = resources.network("nat")
    contract("Network", nat)
    assert nat["gateway_ip"] == str(next(ipaddress.ip_network(nat["cidr"]).hosts()))
    assert nat["bridge_name"].startswith("pfbr-")
    assert nat["workloads"] == 0
    assert nat["capacity"] > 0

    overlapping = owner_cloud.request(
        "POST",
        f"{CLOUD}/networks",
        {"project_id": project_id, "name": "overlap", "kind": "nat", "cidr": nat["cidr"]},
    )
    assert overlapping.status_code == 409

    duplicate = owner_cloud.request(
        "POST",
        f"{CLOUD}/networks",
        {"project_id": project_id, "name": nat["name"], "kind": "nat", "cidr": _free_cidr()},
    )
    assert duplicate.status_code == 409

    lab = resources.network("lab")
    assert "gateway_ip" not in lab, "a lab network has no host address"

    listed = owner_cloud.get(f"{CLOUD}/networks?project_id={project_id}")
    contract("NetworkList", listed)
    assert {n["id"] for n in listed["items"]} == {nat["id"], lab["id"]}

    # Destructive operations repeat the resource's name.
    path = f"{CLOUD}/networks/{lab['id']}"
    refused = owner_cloud.request("DELETE", path)
    assert refused.status_code == 428
    assert refused.json()["type"] == "https://parallelf.dev/problems/confirmation-required"
    contract("Problem", refused.json())
    assert owner_cloud.request("DELETE", f"{path}?confirm=wrong-name").status_code == 428
    assert owner_cloud.request("DELETE", f"{path}?confirm={lab['name']}").status_code == 204
    resources.networks.remove(lab)

    assert owner_cloud.get(path)["deleted_at"]
    listed = owner_cloud.get(f"{CLOUD}/networks?project_id={project_id}")
    assert [n["id"] for n in listed["items"]] == [nat["id"]]


def test_workload_admission_rules(owner_cloud: Cloud, resources: Resources) -> None:
    project_id = resources.project_id
    lab = resources.network("lab")

    def admit(template: str, network_id: str, **extra: Any) -> httpx.Response:
        body = {
            "project_id": project_id,
            "name": f"it-admit-{secrets.token_hex(3)}",
            "template": template,
            "network_id": network_id,
            **extra,
        }
        return owner_cloud.request("POST", f"{CLOUD}/workloads", body)

    def rejected(response: httpx.Response) -> set[tuple[str, str]]:
        assert response.status_code == 422, response.text
        return {(e["field"], e["code"]) for e in response.json()["errors"]}

    # Lab networks have no DHCP: only VMs that configure themselves.
    assert ("network_id", "lab_requires_vm") in rejected(admit("alpine-sleeper", lab["id"]))
    assert ("template", "lab_requires_static_network") in rejected(admit("cirros", lab["id"]))

    assert rejected(admit("no-such-template", lab["id"])) == {("template", "not_found")}
    assert {f for f, _ in rejected(admit("cirros", lab["id"], flavor="pf.huge"))} == {"flavor"}
    assert {f for f, _ in rejected(admit("cirros", lab["id"], ssh_authorized_keys=["nope"]))} == {
        "ssh_authorized_keys"
    }

    # A network holds one kind of workload.
    nat = resources.network("nat")
    container = resources.workload(nat, "alpine-sleeper")
    assert container["kind"] == "container"
    assert ("network_id", "mixed_kinds") in rejected(admit("cirros", nat["id"]))
    resources.delete_workload(container)


def test_quota_admission(owner_cloud: Cloud, resources: Resources, contract: ContractCheck) -> None:
    project_id = resources.project_id
    status = owner_cloud.get(f"{CLOUD}/quotas/{project_id}")
    contract("QuotaStatus", status)
    assert status["quota"]["is_default"] is True
    assert status["usage"] == {"vcpus": 0, "memory_mib": 0, "disk_gib": 0, "workloads": 0}

    limits = {"max_vcpus": 4, "max_memory_mib": 128, "max_disk_gib": 10, "max_workloads": 5}
    updated = owner_cloud.request("PUT", f"{CLOUD}/quotas/{project_id}", limits)
    assert updated.status_code == 200, updated.text
    contract("QuotaStatus", updated.json())
    assert updated.json()["quota"]["is_default"] is False

    network = resources.network("nat")
    over = owner_cloud.request(
        "POST",
        f"{CLOUD}/workloads",
        {
            "project_id": project_id,
            "name": "it-too-big",
            "template": "alpine-sleeper",
            "flavor": "pf.nano",
            "network_id": network["id"],
        },
    )
    assert over.status_code == 422
    problem = over.json()
    assert problem["type"] == "https://parallelf.dev/problems/quota-exceeded"
    assert {e["field"] for e in problem["errors"]} == {"memory_mib"}

    entries = owner_cloud.get(f"{CLOUD}/audit?resource_type=quota&resource_id={project_id}")
    assert [e["action"] for e in entries["items"]] == ["cloud.quotas.update"]


def test_changes_are_audited_and_emitted_as_events(
    owner_cloud: Cloud,
    resources: Resources,
    contract: ContractCheck,
    cloud_db: psycopg.Connection[tuple[Any, ...]],
) -> None:
    network = resources.network("nat")

    page = owner_cloud.get(f"{CLOUD}/audit?resource_id={network['id']}")
    contract("AuditPage", page)
    [entry] = page["items"]
    assert entry["action"] == "cloud.networks.create"
    assert entry["actor_name"] == "owner"
    assert entry["outcome"] == "success"
    assert entry["project_id"] == resources.project_id

    verification = owner_cloud.get(f"{CLOUD}/audit/verify")
    contract("AuditVerification", verification)
    assert verification["valid"] is True
    assert verification["entries"] >= entry["seq"]

    rows = cloud_db.execute(
        "SELECT subject, event_type, convert_from(payload, 'UTF8'), headers FROM cloud.outbox"
        " WHERE headers->>'ce-subject' = %s",
        (f"network/{network['id']}",),
    ).fetchall()
    assert len(rows) == 1
    subject, event_type, payload, headers = rows[0]
    assert subject == "pf.cloud.evt.network.created"
    assert event_type == "parallelf.cloud.v1.NetworkCreated"
    assert headers["ce-source"] == "/parallelf/cloud/pf-cloudd"
    assert headers["ce-pfproject"] == resources.project_id
    assert json.loads(payload)["cidr"] == network["cidr"]


# --- Real workloads on a compute node ----------------------------------------


def test_compute_node_reports_capacity_and_metrics(
    owner_cloud: Cloud, ready_node: dict[str, Any], contract: ContractCheck
) -> None:
    contract("Node", ready_node)
    assert ready_node["kvm"] is True, "the node cannot run VMs"
    allocatable = ready_node["allocatable"]
    assert allocatable["vcpus"] > 0
    assert allocatable["memory_mib"] == ready_node["memory_mib"] - ready_node["reserved_memory_mib"]

    deadline = time.monotonic() + 30
    points: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not points:
        metrics = owner_cloud.get(f"{CLOUD}/nodes/{ready_node['id']}/metrics?window=15m")
        contract("Metrics", metrics)
        points = metrics["points"]
        time.sleep(2)
    assert points, "the node reported no metrics"
    assert 0 <= points[-1]["cpu_percent"] <= 100
    assert points[-1]["memory_used_mib"] > 0


def test_vm_lifecycle(
    owner_cloud: Cloud,
    resources: Resources,
    ready_node: dict[str, Any],
    contract: ContractCheck,
) -> None:
    network = resources.network("nat")
    vm = resources.workload(network, "cirros")
    contract("Workload", vm)
    assert vm["state"] in ("PENDING", "SCHEDULED")
    assert ipaddress.ip_address(vm["ip"]) in ipaddress.ip_network(network["cidr"])
    assert vm["mac"].startswith("52:54:00:")

    vm = owner_cloud.wait_for(vm["id"], "RUNNING", 300)
    assert vm["node_id"]
    assert vm["observed_generation"] == vm["generation"]
    domain = f"pf-{vm['id']}"
    assert "running" in _run("virsh", "-c", "qemu:///system", "domstate", domain, sudo=True).stdout

    # The guest took the reserved address over DHCP: the host reaches it.
    assert _pings(vm["ip"], 120), f"no reply from {vm['ip']}"

    node = owner_cloud.node(vm["node_id"])
    assert node["allocated"]["memory_mib"] >= vm["memory_mib"]

    deadline = time.monotonic() + 60
    points: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not points:
        points = owner_cloud.get(f"{CLOUD}/workloads/{vm['id']}/metrics?window=15m")["points"]
        time.sleep(3)
    assert points, "no workload metrics"

    assert owner_cloud.request("POST", f"{CLOUD}/workloads/{vm['id']}/stop").status_code == 202
    owner_cloud.wait_for(vm["id"], "STOPPED", 150)
    # A stopped workload keeps its resources and address.
    assert owner_cloud.workload(vm["id"])["ip"] == vm["ip"]
    assert owner_cloud.request("POST", f"{CLOUD}/workloads/{vm['id']}/stop").status_code == 409

    assert owner_cloud.request("POST", f"{CLOUD}/workloads/{vm['id']}/start").status_code == 202
    owner_cloud.wait_for(vm["id"], "RUNNING", 120)

    events = owner_cloud.get(f"{CLOUD}/workloads/{vm['id']}/events")
    contract("WorkloadEventList", events)
    states = [e["message"] for e in events["items"] if e["type"] == "state"]
    assert any(m.endswith("→ RUNNING") for m in states), states
    assert any(m.endswith("→ STOPPED") for m in states), states

    refused = owner_cloud.request("DELETE", f"{CLOUD}/workloads/{vm['id']}")
    assert refused.status_code == 428
    resources.delete_workload(vm)
    deleted = owner_cloud.workload(vm["id"])
    assert deleted["deleted_at"]
    assert not _domain_exists(vm["id"])
    assert not _exists(AGENT_DATA_DIR / "instances" / vm["id"])

    actions = [
        e["action"] for e in owner_cloud.get(f"{CLOUD}/audit?resource_id={vm['id']}")["items"]
    ]
    assert actions[::-1] == [
        "cloud.workloads.create",
        "cloud.workloads.stop",
        "cloud.workloads.start",
        "cloud.workloads.delete",
    ]


def test_container_workload_is_confined(
    owner_cloud: Cloud, resources: Resources, ready_node: dict[str, Any]
) -> None:
    if not ready_node["docker"]:
        pytest.skip("the node has no container runtime")
    network = resources.network("nat")
    container = resources.workload(network, "alpine-sleeper")
    container = owner_cloud.wait_for(container["id"], "RUNNING", 180)

    inspected = json.loads(_run("docker", "inspect", f"pf-{container['id']}").stdout)[0]
    host = inspected["HostConfig"]
    assert host["CapDrop"] == ["ALL"]
    assert not host["CapAdd"]
    assert "no-new-privileges:true" in host["SecurityOpt"]
    assert host["Memory"] == container["memory_mib"] * 1024 * 1024
    assert host["NanoCpus"] == container["vcpus"] * 1_000_000_000
    assert host["PidsLimit"] > 0
    assert host["RestartPolicy"]["Name"] == "no"
    assert not host["Privileged"]
    assert "@sha256:" in inspected["Config"]["Image"]
    assert inspected["Config"]["Labels"]["io.parallelf.workload_id"] == container["id"]
    [endpoint] = inspected["NetworkSettings"]["Networks"].values()
    assert endpoint["IPAddress"] == container["ip"]
    assert _pings(container["ip"], 30)

    assert (
        owner_cloud.request("POST", f"{CLOUD}/workloads/{container['id']}/stop").status_code == 202
    )
    owner_cloud.wait_for(container["id"], "STOPPED", 60)
    resources.delete_workload(container)
    assert _run("docker", "inspect", f"pf-{container['id']}", check=False).returncode != 0


def test_lab_network_is_isolated(
    owner_cloud: Cloud, resources: Resources, ready_node: dict[str, Any]
) -> None:
    lab = resources.network("lab")
    # Ubuntu configures its own address from cloud-init network-config:
    # a lab network has no DHCP, no host address and no route out.
    vm = resources.workload(lab, "ubuntu-24.04")
    vm = owner_cloud.wait_for(vm["id"], "RUNNING", 600)

    bridge = lab["bridge_name"]
    addresses = _run("ip", "-4", "-o", "addr", "show", "dev", bridge).stdout
    assert "inet " not in addresses, f"the lab bridge has a host address: {addresses}"
    definition = _run("virsh", "-c", "qemu:///system", "net-dumpxml", bridge, sudo=True).stdout
    assert "<forward" not in definition and "<ip" not in definition, definition
    assert not _pings(vm["ip"], 5), "the host must not reach a lab network"

    # The guest reports its interfaces on the serial console once cloud-init
    # has applied the static configuration.
    log = AGENT_DATA_DIR / "instances" / vm["id"] / "console.log"
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        console = _run("cat", str(log), sudo=True, check=False).stdout
        if vm["ip"] in console:
            break
        time.sleep(5)
    else:
        pytest.fail(f"the guest never reported {vm['ip']} on its console")

    resources.delete_workload(vm, timeout=240)


# --- Disruptive: failures and restarts ---------------------------------------

disruptive = pytest.mark.skipif(
    not DISRUPTIVE, reason="set PF_CLOUD_DISRUPTIVE_TESTS=1 (stops services, needs sudo)"
)


@disruptive
def test_agent_outage_marks_node_and_recovers(
    owner_cloud: Cloud, resources: Resources, ready_node: dict[str, Any]
) -> None:
    network = resources.network("nat")
    vm = resources.workload(network, "cirros")
    vm = owner_cloud.wait_for(vm["id"], "RUNNING", 300)

    _run("systemctl", "stop", "pf-node-agent", sudo=True)
    try:
        deadline = time.monotonic() + 90
        while owner_cloud.node(vm["node_id"])["status"] != "NOT_READY":
            assert time.monotonic() < deadline, "the node was not marked NOT_READY"
            time.sleep(3)
        # The control plane no longer knows the workload's state...
        assert owner_cloud.workload(vm["id"])["state"] == "UNKNOWN"
        # ...but stopping the agent leaves workloads running.
        domstate = _run("virsh", "-c", "qemu:///system", "domstate", f"pf-{vm['id']}", sudo=True)
        assert "running" in domstate.stdout
    finally:
        _run("systemctl", "start", "pf-node-agent", sudo=True)

    deadline = time.monotonic() + 60
    while owner_cloud.node(vm["node_id"])["status"] != "READY":
        assert time.monotonic() < deadline, "the node did not come back"
        time.sleep(2)
    owner_cloud.wait_for(vm["id"], "RUNNING", 60)
    assert _pings(vm["ip"], 30)


@disruptive
def test_control_plane_restart_keeps_state(
    owner_cloud: Cloud, resources: Resources, ready_node: dict[str, Any]
) -> None:
    network = resources.network("nat")
    vm = resources.workload(network, "cirros")
    vm = owner_cloud.wait_for(vm["id"], "RUNNING", 300)

    compose = [
        "docker",
        "compose",
        "--env-file",
        str(REPO_ROOT / ".env"),
        "-f",
        str(REPO_ROOT / "deploy" / "compose" / "compose.yaml"),
    ]
    _run(*compose, "restart", "cloud")
    deadline = time.monotonic() + 90
    while owner_cloud.request("GET", f"{CLOUD}/nodes").status_code != 200:
        assert time.monotonic() < deadline, "pf-cloudd did not come back"
        time.sleep(2)

    after = owner_cloud.workload(vm["id"])
    assert after["state"] == "RUNNING"
    assert after["generation"] == vm["generation"]
    assert _pings(vm["ip"], 30)

    # The restarted control plane still drives the agent.
    assert owner_cloud.request("POST", f"{CLOUD}/workloads/{vm['id']}/stop").status_code == 202
    owner_cloud.wait_for(vm["id"], "STOPPED", 150)
    assert owner_cloud.get(f"{CLOUD}/audit/verify")["valid"] is True


@pytest.fixture
def admin_db() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    url = os.environ.get("PF_TEST_ADMIN_DATABASE_URL", "")
    if not url:
        pytest.fail("PF_TEST_ADMIN_DATABASE_URL is needed to add a broken template")
    with psycopg.connect(url, autocommit=True, connect_timeout=10) as connection:
        yield connection


@disruptive
def test_failed_provisioning_is_reported_cleaned_up_and_retried(
    owner_cloud: Cloud,
    resources: Resources,
    ready_node: dict[str, Any],
    admin_db: psycopg.Connection[tuple[Any, ...]],
) -> None:
    # A template whose image digest does not match what the URL serves, as
    # after a tampered or truncated download.
    name = f"it-broken-{secrets.token_hex(3)}"
    image_id, template_id = (
        str(row[0])
        for row in admin_db.execute("SELECT gen_random_uuid() UNION ALL SELECT gen_random_uuid()")
    )
    admin_db.execute(
        "INSERT INTO cloud.images (id, name, kind, source, sha256, os)"
        " SELECT %s, %s, kind, source, repeat('0', 64), os"
        " FROM cloud.images WHERE name = 'cirros-0.6.2'",
        (image_id, name),
    )
    admin_db.execute(
        "INSERT INTO cloud.templates"
        " (id, name, version, kind, description, image_id, default_flavor_id)"
        " SELECT %s, %s, 1, kind, 'integration test: wrong digest', %s, default_flavor_id"
        " FROM cloud.templates WHERE name = 'cirros' AND version = 1",
        (template_id, name, image_id),
    )
    try:
        network = resources.network("nat")
        vm = resources.workload(network, name)
        vm = owner_cloud.wait_for(vm["id"], "ERROR", 240, allow_error=True)
        assert "checksum mismatch" in vm["status_message"], vm
        # Nothing of the failed attempt is left on the node.
        assert not _domain_exists(vm["id"])
        assert not _exists(AGENT_DATA_DIR / "instances" / vm["id"])

        # Retrying is only allowed from ERROR; with the digest corrected
        # (standing in for a fixed mirror) the retry succeeds.
        admin_db.execute(
            "UPDATE cloud.images"
            " SET sha256 = (SELECT sha256 FROM cloud.images WHERE name = 'cirros-0.6.2')"
            " WHERE id = %s",
            (image_id,),
        )
        assert owner_cloud.request("POST", f"{CLOUD}/workloads/{vm['id']}/retry").status_code == 202
        retried = owner_cloud.wait_for(vm["id"], "RUNNING", 300)
        assert retried["generation"] > vm["generation"]
        assert owner_cloud.request("POST", f"{CLOUD}/workloads/{vm['id']}/retry").status_code == 409
        resources.delete_workload(retried)
    finally:
        admin_db.execute(
            "UPDATE cloud.templates SET deprecated = true WHERE id = %s", (template_id,)
        )
