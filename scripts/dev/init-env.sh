#!/bin/sh
# Creates .env from .env.example, giving every secret a random value.
#
# When .env already exists, only the keys it lacks are added (with fresh
# secrets), so upgrading to a version that needs new settings is one
# `make init`. Existing values are never changed.
set -eu

cd "$(dirname "$0")/../.."

random_secret() {
  # 32 hex characters (128 bits) from the kernel CSPRNG.
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

render() { # line -> line with a generated secret if needed
  case "$1" in
    *=generate-me) printf '%s=%s\n' "${1%%=*}" "$(random_secret)" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

umask 077
if [ ! -f .env ]; then
  : > .env
  while IFS= read -r line || [ -n "$line" ]; do
    render "$line" >> .env
  done < .env.example
  echo "Created .env with generated secrets."
  echo "Development sign-in: user \"owner\" or \"viewer\"; passwords are PF_DEV_OWNER_PASSWORD and PF_DEV_VIEWER_PASSWORD in .env."
  exit 0
fi

added=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    '#'*|'') continue ;;
  esac
  key=${line%%=*}
  if ! grep -q "^${key}=" .env; then
    render "$line" >> .env
    added="$added $key"
  fi
done < .env.example
if [ -n "$added" ]; then
  echo "Added to .env:$added"
else
  echo ".env is up to date."
fi
