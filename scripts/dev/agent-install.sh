#!/bin/sh
# Installs pf-node-agent as a systemd service on this host.
#
#   sudo PF_CLOUD_JOIN_TOKEN=... scripts/dev/agent-install.sh bin/pf-node-agent
#
# The join token is written to /etc/parallelf/node-agent.env (mode 0600).
set -eu

binary="${1:?usage: $0 <path to pf-node-agent>}"
: "${PF_CLOUD_JOIN_TOKEN:?PF_CLOUD_JOIN_TOKEN must be set (it is in the platform's .env)}"
cloud_url="${PF_AGENT_CLOUD_URL:-http://localhost:9102}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi
if [ ! -d /run/systemd/system ]; then
  echo "systemd is not running. On WSL2 add [boot] systemd=true to /etc/wsl.conf, or run the agent in the foreground with: make agent" >&2
  exit 1
fi

here=$(cd "$(dirname "$0")/../.." && pwd)
install -m 0755 "$binary" /usr/local/bin/pf-node-agent
install -d -m 0700 /etc/parallelf
umask 077
cat > /etc/parallelf/node-agent.env <<ENV
PF_AGENT_CLOUD_URL=$cloud_url
PF_AGENT_JOIN_TOKEN=$PF_CLOUD_JOIN_TOKEN
PF_AGENT_DATA_DIR=/var/lib/parallelf/cloud
PF_AGENT_RESERVED_MEMORY_MIB=${PF_AGENT_RESERVED_MEMORY_MIB:-4096}
PF_AGENT_RESERVED_CPUS=${PF_AGENT_RESERVED_CPUS:-1}
PF_LOG_LEVEL=${PF_LOG_LEVEL:-info}
ENV
install -m 0644 "$here/deploy/systemd/pf-node-agent.service" /etc/systemd/system/pf-node-agent.service
systemctl daemon-reload
systemctl enable pf-node-agent >/dev/null 2>&1
systemctl restart pf-node-agent
echo "pf-node-agent installed and started. Logs: journalctl -u pf-node-agent -f"
