"""A WireGuard client in a network namespace, for checking the VPN locally.

The namespace stands in for a user's device: it has its own key pair, its
own routing table and reaches the gateway's public endpoint over a veth
pair, exactly as a remote device would over the internet. Needs root (or
passwordless sudo) and wireguard-tools.
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import time
from typing import Any

HOST_VETH = "pfvpn-h0"
NS_VETH = "pfvpn-c0"
HOST_ADDR = "172.31.250.1"
NS_ADDR = "172.31.250.2"


def _sudo(argv: list[str]) -> list[str]:
    return argv if os.geteuid() == 0 else ["sudo", "-n", *argv]


def run(
    *argv: str, stdin: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        _sudo(list(argv)), input=stdin, capture_output=True, text=True, timeout=60, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def generate_keys() -> tuple[str, str]:
    """A fresh X25519 key pair, generated locally (the private key stays here)."""
    private = subprocess.run(
        ["wg", "genkey"], capture_output=True, text=True, check=True
    ).stdout.strip()
    public = subprocess.run(
        ["wg", "pubkey"], input=private, capture_output=True, text=True, check=True
    ).stdout.strip()
    return private, public


class Client:
    def __init__(self, namespace: str = "pfvpn-client") -> None:
        self.ns = namespace

    def exec(self, *argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run("ip", "netns", "exec", self.ns, *argv, check=check)

    def up(self, private_key: str, config: dict[str, Any], preshared_key: str = "") -> None:
        """Connects with the configuration pf-vpnd returned at enrolment."""
        self.down()
        run("ip", "netns", "add", self.ns)
        run("ip", "link", "add", HOST_VETH, "type", "veth", "peer", "name", NS_VETH)
        run("ip", "link", "set", NS_VETH, "netns", self.ns)
        run("ip", "address", "add", f"{HOST_ADDR}/30", "dev", HOST_VETH)
        run("ip", "link", "set", HOST_VETH, "up")
        self.exec("ip", "address", "add", f"{NS_ADDR}/30", "dev", NS_VETH)
        self.exec("ip", "link", "set", NS_VETH, "up")
        self.exec("ip", "link", "set", "lo", "up")
        # Everything not routed into the tunnel goes to the host, which owns
        # the gateway's public endpoint address.
        self.exec("ip", "route", "add", "default", "via", HOST_ADDR)

        self.exec("ip", "link", "add", "wg0", "type", "wireguard")
        with tempfile.TemporaryDirectory() as tmp:
            key_file = os.path.join(tmp, "private.key")
            with open(key_file, "w", encoding="ascii") as f:
                f.write(private_key + "\n")
            os.chmod(key_file, 0o600)
            args = [
                "wg",
                "set",
                "wg0",
                "private-key",
                key_file,
                "peer",
                config["gateway_public_key"],
            ]
            args += ["endpoint", config["endpoint"], "allowed-ips", ",".join(config["allowed_ips"])]
            args += ["persistent-keepalive", str(config["persistent_keepalive"])]
            if preshared_key:
                psk_file = os.path.join(tmp, "psk")
                with open(psk_file, "w", encoding="ascii") as f:
                    f.write(preshared_key + "\n")
                os.chmod(psk_file, 0o600)
                args += ["preshared-key", psk_file]
            self.exec(*args)
        self.exec("ip", "address", "add", config["address"], "dev", "wg0")
        self.exec("ip", "link", "set", "wg0", "up")
        for cidr in config["allowed_ips"]:
            self.exec("ip", "route", "replace", cidr, "dev", "wg0")

    def down(self) -> None:
        run("ip", "netns", "delete", self.ns, check=False)
        run("ip", "link", "delete", HOST_VETH, check=False)

    def ping(self, address: str, timeout: int = 2) -> bool:
        return (
            self.exec("ping", "-c", "1", "-W", str(timeout), address, check=False).returncode == 0
        )

    def tcp(self, address: str, port: int, timeout: float = 2.0) -> bool:
        """Whether a TCP connection to address:port succeeds from the device."""
        code = (
            "import socket,sys\n"
            f"s=socket.socket(); s.settimeout({timeout})\n"
            f"sys.exit(0 if s.connect_ex(({address!r},{port}))==0 else 1)\n"
        )
        return self.exec("python3", "-c", code, check=False).returncode == 0

    def handshake_age(self) -> int | None:
        out = self.exec("wg", "show", "wg0", "latest-handshakes", check=False).stdout.split()
        if len(out) < 2 or out[1] == "0":
            return None
        return int(time.time()) - int(out[1])


def gateway_has_peer(public_key: str, interface: str = "wg-pf0") -> bool:
    out = run("wg", "show", interface, "peers", check=False).stdout.split()
    return public_key in out


def listen(address: str, port: int) -> socket.socket:
    """A TCP listener on the gateway side (accepts and closes)."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((address, port))
    s.listen(16)
    return s
