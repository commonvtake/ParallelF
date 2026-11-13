#!/bin/sh
# Waits until every component of the local stack answers, or fails after
# PF_WAIT_TIMEOUT seconds (default 300).
set -eu

TIMEOUT="${PF_WAIT_TIMEOUT:-300}"
GATEWAY_URL="${PF_GATEWAY_URL:-http://localhost:8000}"
DASHBOARD_URL="${PF_DASHBOARD_URL:-http://localhost:3000}"
KEYCLOAK_URL="${PF_KEYCLOAK_URL:-http://localhost:8080}"

wait_for() {
  name=$1
  url=$2
  start=$(date +%s)
  printf 'waiting for %-18s' "$name"
  while :; do
    code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$url" 2>/dev/null || true)
    if [ "$code" = "200" ]; then
      echo " ready ($(( $(date +%s) - start ))s)"
      return 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$TIMEOUT" ]; then
      echo " TIMED OUT after ${TIMEOUT}s (last HTTP status: ${code:-none})"
      echo "Inspect the stack with: make ps   and   make logs" >&2
      return 1
    fi
    printf '.'
    sleep 2
  done
}

wait_for "identity provider" "$KEYCLOAK_URL/realms/parallelf/.well-known/openid-configuration"
wait_for "gateway" "$GATEWAY_URL/readyz"
wait_for "dashboard" "$DASHBOARD_URL/healthz"
echo "The stack is up: $DASHBOARD_URL"
