#!/bin/sh
# Prepares this Linux host to run the ParallelF network sensor: Suricata
# (and ping for discovery scopes). The distribution's own Suricata service
# is disabled, because it would capture on the host's uplink: the sensor
# runs Suricata itself, on ParallelF's interfaces only (wg-pf0, pfbr-*).
#
#   sudo scripts/dev/ng-sensor-setup.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

echo "Installing suricata and iputils-ping..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends suricata iputils-ping >/dev/null
if [ -d /run/systemd/system ]; then
  systemctl disable --now suricata >/dev/null 2>&1 || true
fi
mkdir -p /var/lib/parallelf/netguard
chmod 0700 /var/lib/parallelf/netguard

echo
echo "Checks:"
status=0
if command -v suricata >/dev/null 2>&1; then
  echo "  ok    $(suricata -V 2>&1 | head -n 1)"
else
  echo "  FAIL  suricata missing"
  status=1
fi
if command -v ping >/dev/null 2>&1; then echo "  ok    ping"; else echo "  FAIL  ping missing"; status=1; fi
if [ -d /run/systemd/system ] && systemctl is-active --quiet suricata; then
  echo "  FAIL  the distribution's suricata service is still running"
  status=1
else
  echo "  ok    no other Suricata instance is capturing"
fi
exit $status
