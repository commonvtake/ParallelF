#!/bin/sh
# Smoke test of the running local stack. Needs only curl.
#
#   make verify
#
# Exercises the path a real request takes: identity provider -> gateway ->
# service -> database, plus the dashboard's unauthenticated behaviour.
set -eu

cd "$(dirname "$0")/../.."

GATEWAY_URL="${PF_GATEWAY_URL:-http://localhost:8000}"
DASHBOARD_URL="${PF_DASHBOARD_URL:-http://localhost:3000}"

passed=0
failed=0
body_file=$(mktemp)
trap 'rm -f "$body_file"' EXIT

pass() { passed=$((passed + 1)); printf '  PASS  %s\n' "$1"; }
fail() { failed=$((failed + 1)); printf '  FAIL  %s\n        %s\n' "$1" "$2"; }

# request METHOD URL [curl args...] -> sets $status, body in $body_file
request() {
  method=$1
  url=$2
  shift 2
  status=$(curl -s -m 10 -o "$body_file" -w '%{http_code}' -X "$method" "$@" "$url" || true)
}

expect_status() { # description expected
  if [ "$status" = "$2" ]; then pass "$1"; else fail "$1" "expected HTTP $2, got $status: $(head -c 300 "$body_file")"; fi
}

expect_body() { # description pattern
  if grep -q -- "$2" "$body_file"; then pass "$1"; else fail "$1" "response does not contain $2: $(head -c 300 "$body_file")"; fi
}

echo "Health endpoints"
request GET "$GATEWAY_URL/healthz"
expect_status "gateway liveness answers 200" 200
expect_body "gateway identifies itself" '"service":"pf-gateway"'
request GET "$GATEWAY_URL/readyz"
expect_status "gateway readiness answers 200" 200
request GET "$DASHBOARD_URL/healthz"
expect_status "dashboard liveness answers 200" 200

echo "Authentication"
request GET "$GATEWAY_URL/api/v1/core/me"
expect_status "API rejects a request without a token (401)" 401
expect_body "error is an RFC 9457 problem" '"type":"https://parallelf.dev/problems/unauthorized"'
request GET "$GATEWAY_URL/api/v1/core/me" -H "Authorization: Bearer not-a-token"
expect_status "API rejects an invalid token (401)" 401

if ! owner_token=$(scripts/dev/token.sh owner); then
  fail "identity provider issues a token for owner" "see the message above"
  echo
  echo "$passed passed, $failed failed"
  exit 1
fi
pass "identity provider issues a token for owner"
viewer_token=$(scripts/dev/token.sh viewer)
pass "identity provider issues a token for viewer"

request GET "$GATEWAY_URL/api/v1/core/me" -H "Authorization: Bearer $owner_token"
expect_status "owner can read their profile" 200
expect_body "profile carries the owner role" '"roles":\["owner"\]'

echo "Platform status"
request GET "$GATEWAY_URL/api/v1/system/status" -H "Authorization: Bearer $owner_token"
expect_status "status endpoint answers 200" 200
expect_body "every component is operational" '^{"status":"ok"'
expect_body "database is reported through pf-core" '"name":"postgres","kind":"dependency","status":"ok"'

echo "Projects (gateway -> pf-core -> PostgreSQL)"
slug="verify-$(date +%s)"
request POST "$GATEWAY_URL/api/v1/core/projects" -H "Authorization: Bearer $owner_token" \
  -H "Content-Type: application/json" -d "{\"slug\":\"$slug\",\"name\":\"Smoke test\"}"
expect_status "owner creates a project (201)" 201
project_id=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$body_file")
request POST "$GATEWAY_URL/api/v1/core/projects" -H "Authorization: Bearer $viewer_token" \
  -H "Content-Type: application/json" -d '{"slug":"viewer-attempt","name":"Viewer"}'
expect_status "viewer cannot create a project (403)" 403
request GET "$GATEWAY_URL/api/v1/core/projects/$project_id" -H "Authorization: Bearer $viewer_token"
expect_status "viewer can read the project" 200
request DELETE "$GATEWAY_URL/api/v1/core/projects/$project_id" -H "Authorization: Bearer $owner_token"
expect_status "owner deletes the project (204)" 204
request GET "$GATEWAY_URL/api/v1/core/projects/$project_id" -H "Authorization: Bearer $owner_token"
expect_status "deleted project is gone (404)" 404

echo "AI service (gateway -> pf-aid)"
request GET "$GATEWAY_URL/api/v1/ai/info" -H "Authorization: Bearer $owner_token"
expect_status "AI info answers 200" 200
expect_body "capabilities are reported as not implemented" '"status":"not_implemented"'

echo "Dashboard"
redirect=$(curl -s -m 10 -o /dev/null -w '%{http_code} %{redirect_url}' "$DASHBOARD_URL/" || true)
case "$redirect" in
  "307 "*"/login") pass "dashboard sends anonymous visitors to /login" ;;
  *) fail "dashboard sends anonymous visitors to /login" "got: $redirect" ;;
esac
request GET "$DASHBOARD_URL/bff/api/core/me"
expect_status "dashboard API proxy requires a session (401)" 401

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
