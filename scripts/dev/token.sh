#!/bin/sh
# Prints an access token for a development user (default: owner).
#
#   scripts/dev/token.sh [owner|viewer]
#
# Uses the password grant of the local realm's "parallelf-dev-cli" client.
# Reads PF_DEV_OWNER_PASSWORD / PF_DEV_VIEWER_PASSWORD from the environment
# (the Makefile exports them from .env).
set -eu

user="${1:-owner}"
case "$user" in
  owner) password="${PF_DEV_OWNER_PASSWORD:?PF_DEV_OWNER_PASSWORD is not set; run through make or export it from .env}" ;;
  viewer) password="${PF_DEV_VIEWER_PASSWORD:?PF_DEV_VIEWER_PASSWORD is not set; run through make or export it from .env}" ;;
  *) echo "usage: $0 [owner|viewer]" >&2; exit 2 ;;
esac

KEYCLOAK_URL="${PF_KEYCLOAK_URL:-http://localhost:8080}"

response=$(curl -sS -m 10 \
  -d grant_type=password \
  -d client_id=parallelf-dev-cli \
  -d "username=$user" \
  --data-urlencode "password=$password" \
  "$KEYCLOAK_URL/realms/parallelf/protocol/openid-connect/token")

token=$(printf '%s' "$response" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -z "$token" ]; then
  echo "could not obtain a token for $user: $response" >&2
  exit 1
fi
printf '%s\n' "$token"
