#!/bin/sh
# Prepares this Linux host (Ubuntu 24.04, including WSL2) to run ParallelF
# Cloud workloads: KVM, libvirt, QEMU and the cloud-init seed tool.
#
#   sudo scripts/dev/cloud-host-setup.sh
#
# Docker is expected to be installed already (it runs the platform).
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

echo "Installing libvirt, QEMU/KVM, qemu-img and genisoimage..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  libvirt-daemon-system libvirt-clients qemu-system-x86 qemu-utils genisoimage >/dev/null

if [ -d /run/systemd/system ]; then
  systemctl enable --now libvirtd >/dev/null 2>&1 || true
fi

mkdir -p /var/lib/parallelf/cloud
chmod 0755 /var/lib/parallelf /var/lib/parallelf/cloud

echo
echo "Checks:"
status=0
if [ -e /dev/kvm ]; then
  echo "  ok    /dev/kvm exists"
else
  echo "  FAIL  /dev/kvm is missing: enable virtualization in the BIOS; on WSL2 set nestedVirtualization=true in .wslconfig"
  status=1
fi
if virsh -c qemu:///system version >/dev/null 2>&1; then
  echo "  ok    libvirt answers ($(virsh -c qemu:///system version | sed -n 's/^Running hypervisor: //p'))"
else
  echo "  FAIL  libvirt does not answer: is libvirtd running? (systemctl status libvirtd)"
  status=1
fi
for tool in qemu-img genisoimage; do
  if command -v $tool >/dev/null 2>&1; then echo "  ok    $tool"; else echo "  FAIL  $tool missing"; status=1; fi
done
if docker version >/dev/null 2>&1; then echo "  ok    Docker answers"; else echo "  warn  Docker does not answer; container workloads will be disabled"; fi
exit $status
