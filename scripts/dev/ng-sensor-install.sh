#!/bin/sh
# Installs pf-ng-sensor as a systemd service on this host.
#
#   sudo PF_NG_JOIN_TOKEN=... scripts/dev/ng-sensor-install.sh bin/pf-ng-sensor
#
# The join token is written to /etc/parallelf/ng-sensor.env (mode 0600).
set -eu

binary="${1:?usage: $0 <path to pf-ng-sensor>}"
: "${PF_NG_JOIN_TOKEN:?PF_NG_JOIN_TOKEN must be set (it is in the platform's .env)}"
netguard_url="${PF_NGS_NETGUARD_URL:-http://localhost:9104}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
if [ ! -d /run/systemd/system ]; then
  echo "systemd is not running. On WSL2 add [boot] systemd=true to /etc/wsl.conf, or run the sensor in the foreground with: make ng-sensor" >&2
  exit 1
fi

here=$(cd "$(dirname "$0")/../.." && pwd)
install -m 0755 "$binary" /usr/local/bin/pf-ng-sensor
install -d -m 0700 /etc/parallelf
umask 077
cat > /etc/parallelf/ng-sensor.env <<ENV
PF_NGS_NETGUARD_URL=$netguard_url
PF_NGS_JOIN_TOKEN=$PF_NG_JOIN_TOKEN
PF_NGS_DATA_DIR=/var/lib/parallelf/netguard
PF_NGS_VPN_INTERFACE=${PF_NGS_VPN_INTERFACE:-wg-pf0}
PF_NGS_EXTRA_RULES=${PF_NGS_EXTRA_RULES:-}
PF_LOG_LEVEL=${PF_LOG_LEVEL:-info}
ENV
install -m 0644 "$here/deploy/systemd/pf-ng-sensor.service" /etc/systemd/system/pf-ng-sensor.service
systemctl daemon-reload
systemctl enable pf-ng-sensor >/dev/null 2>&1
systemctl restart pf-ng-sensor
echo "pf-ng-sensor installed and started. Logs: journalctl -u pf-ng-sensor -f"
