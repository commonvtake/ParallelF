#!/bin/sh
# Installs pf-wg-agent as a systemd service on this host.
#
#   sudo PF_VPN_JOIN_TOKEN=... scripts/dev/wg-agent-install.sh bin/pf-wg-agent
#
# The join token is written to /etc/parallelf/wg-agent.env (mode 0600).
set -eu

binary="${1:?usage: $0 <path to pf-wg-agent>}"
: "${PF_VPN_JOIN_TOKEN:?PF_VPN_JOIN_TOKEN must be set (it is in the platform's .env)}"
vpn_url="${PF_WGA_VPN_URL:-http://localhost:9103}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
if [ ! -d /run/systemd/system ]; then
  echo "systemd is not running. On WSL2 add [boot] systemd=true to /etc/wsl.conf, or run the agent in the foreground with: make wg-agent" >&2
  exit 1
fi

here=$(cd "$(dirname "$0")/../.." && pwd)
install -m 0755 "$binary" /usr/local/bin/pf-wg-agent
install -d -m 0700 /etc/parallelf
umask 077
cat > /etc/parallelf/wg-agent.env <<ENV
PF_WGA_VPN_URL=$vpn_url
PF_WGA_JOIN_TOKEN=$PF_VPN_JOIN_TOKEN
PF_WGA_DATA_DIR=/var/lib/parallelf/vpn
PF_WGA_INTERFACE=${PF_WGA_INTERFACE:-wg-pf0}
PF_WGA_LISTEN_PORT=${PF_WGA_LISTEN_PORT:-51820}
PF_WGA_ENDPOINT=${PF_WGA_ENDPOINT:-}
PF_LOG_LEVEL=${PF_LOG_LEVEL:-info}
ENV
install -m 0644 "$here/deploy/systemd/pf-wg-agent.service" /etc/systemd/system/pf-wg-agent.service
systemctl daemon-reload
systemctl enable pf-wg-agent >/dev/null 2>&1
systemctl restart pf-wg-agent
echo "pf-wg-agent installed and started. Logs: journalctl -u pf-wg-agent -f"
