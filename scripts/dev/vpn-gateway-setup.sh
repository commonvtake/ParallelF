#!/bin/sh
# Prepares this Linux host to be the ParallelF VPN gateway: WireGuard
# tools, nftables and conntrack (the kernel module ships with Linux 5.6+).
#
#   sudo scripts/dev/vpn-gateway-setup.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

echo "Installing wireguard-tools, nftables, conntrack and iproute2..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  wireguard-tools nftables conntrack iproute2 >/dev/null
modprobe wireguard 2>/dev/null || true
mkdir -p /var/lib/parallelf/vpn
chmod 0700 /var/lib/parallelf/vpn

echo
echo "Checks:"
status=0
if ip link add pf-wgcheck type wireguard 2>/dev/null; then
  ip link delete pf-wgcheck
  echo "  ok    the kernel supports WireGuard"
else
  echo "  FAIL  cannot create a WireGuard interface (kernel 5.6+ or the wireguard module is needed)"
  status=1
fi
for tool in wg nft conntrack; do
  if command -v $tool >/dev/null 2>&1; then echo "  ok    $tool"; else echo "  FAIL  $tool missing"; status=1; fi
done
exit $status
