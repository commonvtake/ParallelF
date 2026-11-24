#!/bin/sh
# Puts the catalogue's VM images into the node agent's image cache before
# the cloud tests, from a CI cache or with retries and a mirror, so a slow
# or unreachable download site does not fail the run. The agent trusts its
# cache only by file name (the digest); this script verifies each digest.
#
#   scripts/ci/warm-vm-images.sh <download cache dir>
set -eu

cache="${1:?usage: $0 <cache dir>}"
target=/var/lib/parallelf/cloud/images
mkdir -p "$cache"
sudo mkdir -p "$target"

fetch() { # sha256 url...
  sha=$1
  shift
  file="$cache/$sha.qcow2"
  if [ -f "$file" ] && echo "$sha  $file" | sha256sum -c --status; then
    echo "cached   $sha"
  else
    rm -f "$file"
    for url in "$@"; do
      echo "download $url"
      if curl -fsSL --retry 4 --retry-all-errors --connect-timeout 20 --max-time 900 -o "$file.partial" "$url" &&
        echo "$sha  $file.partial" | sha256sum -c --status; then
        mv "$file.partial" "$file"
        break
      fi
      rm -f "$file.partial"
    done
  fi
  [ -f "$file" ] || { echo "could not fetch $sha" >&2; exit 1; }
  sudo install -m 0644 "$file" "$target/$sha.qcow2"
}

# CirrOS 0.6.2 (the cirros template).
fetch 07e44a73e54c94d988028515403c1ed762055e01b83a767edf3c2b387f78ce00 \
  https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img \
  https://github.com/cirros-dev/cirros/releases/download/0.6.2/cirros-0.6.2-x86_64-disk.img
# Ubuntu 24.04 cloud image, release 20261017 (the ubuntu-24.04 template).
fetch 04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94 \
  https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img
