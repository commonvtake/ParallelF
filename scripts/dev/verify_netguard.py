#!/usr/bin/env python3
"""End-to-end check of ParallelF NetGuard over the VPN.

    make verify-netguard

Needs the stack (`make up`), the WireGuard gateway agent
(`make wg-agent-install`), the network sensor (`make ng-sensor-install`) and
root (the device is simulated in a network namespace). Uses only the
standard library and wireguard-tools.

All traffic stays on ParallelF's own tunnel: a device enrolled for this
check sends an IDS canary request, a canary DNS query, DNS queries shaped
like tunnelling, and connection attempts to 25 closed ports of the gateway.
The check then follows the alerts through attribution, triage, an incident
with evidence, and a signed discovery scope that the sensor runs against
the device.
"""

from __future__ import annotations

import hashlib
import secrets
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_vpn as v
import vpnclient

PLATFORM = v.PLATFORM
SCAN_PORTS = range(20001, 20026)
DISCOVERY_PORT = 7777
ALERT_TIMEOUT_S = 90.0
# A listener inside the device for the discovery scope to find.
LISTENER = (
    "import socket,time;s=socket.socket();"
    "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
    f"s.bind(('0.0.0.0',{DISCOVERY_PORT}));s.listen(8);time.sleep(120)"
)


class _Quiet(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_: Any) -> None:
        pass


def dns_query_code(names: list[str]) -> str:
    """Python run inside the device: one UDP DNS query per name."""
    return (
        "import os,socket,struct\n"
        f"names={names!r}\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "for n in names:\n"
        "    q=struct.pack('>HHHHHH',int.from_bytes(os.urandom(2),'big'),0x0100,1,0,0,0)\n"
        "    q+=b''.join(bytes([len(l)])+l.encode() for l in n.split('.'))\n"
        "    q+=b'\\0'+struct.pack('>HH',1,1)\n"
        f"    s.sendto(q,({PLATFORM!r},53))\n"
    )


def scan_code() -> str:
    """Connection attempts to closed ports (each times out quickly)."""
    return (
        "import socket\n"
        f"for p in range({SCAN_PORTS.start},{SCAN_PORTS.stop}):\n"
        "    s=socket.socket(); s.settimeout(0.3)\n"
        f"    s.connect_ex(({PLATFORM!r},p)); s.close()\n"
    )


def alerts_for(ip: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = v.expect("GET", f"/api/v1/network/alerts?ip={ip}&limit=500", 200)[
        "items"
    ]
    return out


def wait_alert(ip: str, match: Any, what: str) -> dict[str, Any]:
    found: dict[str, Any] = {}

    def check() -> bool:
        for a in alerts_for(ip):
            if match(a):
                found.update(a)
                return True
        return False

    elapsed = v.until(check, ALERT_TIMEOUT_S, f"no {what} alert")
    found["_elapsed"] = elapsed
    return found


def main() -> None:
    print("Sensor")
    sensor: dict[str, Any] = {}

    def reporting() -> bool:
        for s in v.expect("GET", "/api/v1/network/sensors", 200)["items"]:
            if s["status"] == "reporting" and "wg-pf0" in s["interfaces"] and not s["engine_error"]:
                sensor.update(s)
                return True
        return False

    v.until(
        reporting, 90, "no sensor reporting on wg-pf0; install it with `make ng-sensor-install`"
    )
    v.ok(
        f"sensor {sensor['name']} reports with {sensor['engine']} "
        f"on {', '.join(sensor['interfaces'])}"
    )

    print("Device")
    private, public = vpnclient.generate_keys()
    name = f"ng-{int(time.time()) % 100000:05d}"
    enrol = v.expect("POST", "/api/v1/vpn/devices", 201, {"name": name, "public_key": public})
    device, config = enrol["device"], enrol["config"]
    address = device["address"]
    path = f"/api/v1/vpn/devices/{device['id']}"
    v.until(lambda: vpnclient.gateway_has_peer(public), 15, "the gateway did not add the peer")

    client = vpnclient.Client()
    server = HTTPServer((PLATFORM, 8000), _Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client.up(private, config)
        v.expect("POST", f"{path}/activate", 200, {"ttl_seconds": 900})
        v.until(lambda: client.ping(PLATFORM, 1), 20, "the device cannot reach the platform")
        v.ok(f"device {name} at {address} is active on the tunnel")

        print("Detections")
        got = client.exec(
            "python3",
            "-c",
            f"import urllib.request;print(urllib.request.urlopen('http://{PLATFORM}:8000/pf-ng-ids-canary',timeout=5).status)",
            check=False,
        )
        if got.stdout.strip() != "200":
            v.fail(f"the canary request did not complete: {got.stderr.strip()}")
        tunnel = [f"{secrets.token_hex(20)}.t.exfil.parallelf.test" for _ in range(3)]
        client.exec("python3", "-c", dns_query_code(["pf-ng-ids-canary.parallelf.test", *tunnel]))
        client.exec("python3", "-c", scan_code(), check=False)

        canary = wait_alert(address, lambda a: a["rule_id"] == "sid:9100001", "HTTP canary")
        v.ok(
            f"IDS: HTTP canary signature 9100001 raised '{canary['title']}' "
            f"({canary['_elapsed']:.1f}s)"
        )
        dns = wait_alert(address, lambda a: a["rule_id"] == "sid:9100002", "DNS canary")
        v.ok(f"IDS: DNS canary signature 9100002 raised ({dns['_elapsed']:.1f}s)")
        anomaly = wait_alert(address, lambda a: a["detector"] == "ng.dns_anomaly", "DNS anomaly")
        v.ok(f"DNS anomaly: {anomaly['title']} — {anomaly['details'].get('reasons')}")
        scan = wait_alert(address, lambda a: a["detector"] == "ng.port_scan", "port scan")
        if scan["severity"] != "high":
            v.fail(f"an unauthorised scan must be high severity: {scan}")
        v.ok(f"port scan: {scan['title']} ({scan['_elapsed']:.1f}s)")

        print("Attribution")
        src = scan["attribution"].get("source") or {}
        if src.get("kind") != "vpn_device" or src.get("entity_id") != device["id"]:
            v.fail(f"the scan is not attributed to the device: {scan['attribution']}")
        v.ok(
            f"the scan is attributed to VPN device {src.get('name')} "
            f"(owner {src.get('owner_subject')})"
        )
        if any(
            a["detector"] == "ng.new_device" and a.get("src_ip") == address
            for a in alerts_for(address)
        ):
            v.fail("an enrolled device must not be reported as a new device")
        v.ok("an enrolled device is not reported as unknown")
        detail = v.expect("GET", f"/api/v1/network/alerts/{scan['id']}", 200)
        flows = [e for e in detail["events"] if e["kind"] == "flow" and e["src_ip"] == address]
        if len(flows) < 20:
            v.fail(f"the scan alert should carry its flows, got {len(flows)}")
        v.ok(f"the alert links {len(flows)} flow records (community ids, raw-line digests)")

        print("Triage")
        code, _ = v.call(
            "POST",
            f"/api/v1/network/alerts/{scan['id']}/status",
            {"status": "suppressed", "suppress_for": "1h"},
        )
        if code != 422:
            v.fail(f"suppressing without a reason must answer 422, got {code}")
        v.expect(
            "POST",
            f"/api/v1/network/alerts/{scan['id']}/status",
            200,
            {"status": "acknowledged", "reason": "verify-netguard"},
        )
        inc = v.expect(
            "POST",
            "/api/v1/network/incidents",
            201,
            {
                "title": f"Scan from VPN device {name}",
                "severity": "high",
                "summary": "Raised by make verify-netguard.",
                "alert_ids": [scan["id"], canary["id"]],
            },
        )
        ev = v.expect(
            "POST",
            f"/api/v1/network/incidents/{inc['id']}/evidence",
            201,
            {"kind": "event", "name": "first scan flow", "ref": str(scan["first_event_id"])},
        )
        req = urllib.request.Request(
            v.GATEWAY + f"/api/v1/network/incidents/{inc['id']}/evidence/{ev['id']}"
        )
        req.add_header("Authorization", f"Bearer {v.token()}")
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
            header = r.headers.get("X-Content-SHA256")
        if hashlib.sha256(body).hexdigest() != ev["sha256"] or header != ev["sha256"]:
            v.fail("the evidence digest does not match its content")
        check = v.expect("GET", f"/api/v1/network/incidents/{inc['id']}/verify-evidence", 200)
        if not check["valid"]:
            v.fail(f"evidence verification failed: {check}")
        v.expect(
            "PATCH",
            f"/api/v1/network/incidents/{inc['id']}",
            200,
            {"status": "investigating", "note": "Scan confirmed as the verification run."},
        )
        full = v.expect("GET", f"/api/v1/network/incidents/{inc['id']}", 200)
        v.ok(
            f"incident with {len(full['alerts'])} alerts, "
            f"evidence sha256 {ev['sha256'][:16]}… verified, "
            f"{len(full['timeline'])} timeline entries"
        )

        print("Discovery scope")
        code, _ = v.call(
            "POST",
            "/api/v1/network/scopes",
            {
                "name": "not-ours",
                "cidrs": ["192.168.77.0/24"],
                "techniques": ["icmp-echo"],
                "authorization_note": "This range is not a ParallelF network.",
            },
        )
        if code != 422:
            v.fail(f"a scope outside ParallelF's networks must answer 422, got {code}")
        v.ok("a scope outside ParallelF's networks is refused")
        client.exec("sh", "-c", f"nohup python3 -c {LISTENER!r} >/dev/null 2>&1 &", check=False)
        scope = v.expect(
            "POST",
            "/api/v1/network/scopes",
            201,
            {
                "name": f"verify-{name}",
                "cidrs": [f"{address}/32"],
                "techniques": ["icmp-echo", "tcp-connect"],
                "ports": [DISCOVERY_PORT, 7778],
                "rate_pps": 10,
                "duration": "10m",
                "authorization_note": (
                    "Owner-approved discovery of the device enrolled by verify-netguard."
                ),
            },
        )

        def discovered() -> bool:
            for a in v.expect("GET", "/api/v1/network/assets", 200)["items"]:
                if a["ip"] == address and DISCOVERY_PORT in a["open_ports"]:
                    return bool(a["attribution"]["kind"] == "vpn_device")
            return False

        elapsed = v.until(discovered, 60, "the signed scope did not run")
        v.ok(
            f"signed scope {scope['name']} ran: {address} up, port {DISCOVERY_PORT} open, "
            f"7778 closed ({elapsed:.1f}s)"
        )
        code, _ = v.call("DELETE", f"/api/v1/network/scopes/{scope['id']}")
        if code != 428:
            v.fail(f"revoking a scope without confirmation must answer 428, got {code}")
        v.expect("DELETE", f"/api/v1/network/scopes/{scope['id']}?confirm={scope['name']}", 200)
        v.ok("scope revoked (confirmation required)")
    finally:
        client.down()
        server.shutdown()
        v.call("DELETE", f"{path}?confirm={name}")

    print("Audit")
    a = v.expect("GET", "/api/v1/network/audit/verify", 200)
    if not a["valid"]:
        v.fail(f"audit chain broken at {a.get('first_invalid_seq')}")
    v.ok(f"audit chain of {a['entries']} entries verifies")
    print(f"\n{v.passed} passed, 0 failed")


if __name__ == "__main__":
    main()
