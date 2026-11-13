#!/bin/sh
# Creates .env from .env.example, giving every secret a random value.
# Does nothing when .env already exists.
set -eu

cd "$(dirname "$0")/../.."

if [ -f .env ]; then
  echo ".env already exists; leaving it unchanged."
  exit 0
fi

random_secret() {
  # 32 hex characters (128 bits) from the kernel CSPRNG.
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

umask 077
: > .env
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *=generate-me) printf '%s=%s\n' "${line%%=*}" "$(random_secret)" >> .env ;;
    *) printf '%s\n' "$line" >> .env ;;
  esac
done < .env.example

echo "Created .env with generated secrets."
echo "Development sign-in: user \"owner\" or \"viewer\"; passwords are PF_DEV_OWNER_PASSWORD and PF_DEV_VIEWER_PASSWORD in .env."
