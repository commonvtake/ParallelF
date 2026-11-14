#!/bin/bash
# Temporary probe: checks on a GitHub runner that the libvirt layout the
# node agent will generate actually boots and networks a guest.
set -euxo pipefail

sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends libvirt-daemon-system libvirt-clients qemu-system-x86 qemu-utils genisoimage >/dev/null
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' | sudo tee /etc/udev/rules.d/99-kvm4all.rules
sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
ls -l /dev/kvm
sudo virsh -c qemu:///system version
dpkg -l | grep -E "^ii  (libvirt-daemon |qemu-system-x86 |genisoimage )" | awk '{print $2, $3}'

D=/var/lib/parallelf/cloud
sudo mkdir -p $D/images $D/instances/probe
sudo curl -fsSL -o $D/images/cirros.qcow2 https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img
echo "07e44a73e54c94d988028515403c1ed762055e01b83a767edf3c2b387f78ce00  $D/images/cirros.qcow2" | sha256sum -c
sudo qemu-img info --output=json $D/images/cirros.qcow2 | grep -E '"virtual-size"|"format"'
sudo qemu-img create -q -f qcow2 -F qcow2 -b $D/images/cirros.qcow2 $D/instances/probe/disk.qcow2 1G

tmp=$(mktemp -d)
printf 'instance-id: probe\nlocal-hostname: probe\n' > $tmp/meta-data
printf '#cloud-config\nhostname: probe\n' > $tmp/user-data
sudo genisoimage -quiet -output $D/instances/probe/seed.iso -volid cidata -joliet -rock $tmp/user-data $tmp/meta-data
sudo chmod 0755 $D $D/images $D/instances $D/instances/probe; sudo chmod 0644 $D/images/cirros.qcow2

cat > $tmp/nat.xml <<'XML'
<network>
  <name>pfbr-probe001</name>
  <bridge name="pfbr-probe001" stp="on" delay="0"/>
  <forward mode="nat"/>
  <ip address="10.42.0.1" prefix="24">
    <dhcp>
      <range start="10.42.0.249" end="10.42.0.254"/>
    </dhcp>
  </ip>
</network>
XML
sudo virsh -c qemu:///system net-define $tmp/nat.xml
sudo virsh -c qemu:///system net-start pfbr-probe001
sudo virsh -c qemu:///system net-update pfbr-probe001 add ip-dhcp-host '<host mac="52:54:00:aa:bb:01" name="probe" ip="10.42.0.2"/>' --live --config
sudo virsh -c qemu:///system net-dumpxml pfbr-probe001

cat > $tmp/lab.xml <<'XML'
<network>
  <name>pfbr-probe002</name>
  <bridge name="pfbr-probe002" stp="on" delay="0"/>
</network>
XML
sudo virsh -c qemu:///system net-define $tmp/lab.xml
sudo virsh -c qemu:///system net-start pfbr-probe002
ip -br addr show pfbr-probe002
sudo virsh -c qemu:///system net-dumpxml pfbr-probe002

cat > $tmp/dom.xml <<XML
<domain type="kvm">
  <name>pf-00000000-0000-7000-8000-000000000001</name>
  <uuid>00000000-0000-7000-8000-000000000001</uuid>
  <memory unit="MiB">256</memory>
  <vcpu>1</vcpu>
  <os><type arch="x86_64" machine="pc">hvm</type><boot dev="hd"/></os>
  <features><acpi/><apic/></features>
  <cpu mode="host-passthrough"/>
  <clock offset="utc"/>
  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>
  <devices>
    <disk type="file" device="disk"><driver name="qemu" type="qcow2"/><source file="$D/instances/probe/disk.qcow2"/><target dev="vda" bus="virtio"/></disk>
    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="$D/instances/probe/seed.iso"/><target dev="hdc" bus="ide"/><readonly/></disk>
    <interface type="network"><mac address="52:54:00:aa:bb:01"/><source network="pfbr-probe001"/><model type="virtio"/></interface>
    <serial type="pty"><log file="$D/instances/probe/console.log" append="off"/><target port="0"/></serial>
    <console type="pty"><target type="serial" port="0"/></console>
    <rng model="virtio"><backend model="random">/dev/urandom</backend></rng>
    <memballoon model="virtio"><stats period="10"/></memballoon>
  </devices>
</domain>
XML
sudo virsh -c qemu:///system define $tmp/dom.xml
sudo virsh -c qemu:///system start pf-00000000-0000-7000-8000-000000000001
start=$(date +%s)
for i in $(seq 1 60); do
  if ping -c1 -W1 10.42.0.2 >/dev/null 2>&1; then echo "PING OK after $(( $(date +%s) - start ))s"; break; fi
  sleep 3
done
sudo virsh -c qemu:///system domstate pf-00000000-0000-7000-8000-000000000001
sudo virsh -c qemu:///system net-dhcp-leases pfbr-probe001 || true
sudo virsh -c qemu:///system domstats --raw --cpu-total --balloon pf-00000000-0000-7000-8000-000000000001
sudo virsh -c qemu:///system list --all --name
sudo virsh -c qemu:///system net-list --all --name
sudo tail -c 3000 $D/instances/probe/console.log || true
sudo virsh -c qemu:///system shutdown pf-00000000-0000-7000-8000-000000000001
for i in $(seq 1 20); do s=$(sudo virsh -c qemu:///system domstate pf-00000000-0000-7000-8000-000000000001); echo "$i $s"; [ "$s" = "shut off" ] && break; sleep 3; done
nproc; grep -E "MemTotal|MemAvailable" /proc/meminfo; df -h /var/lib

echo "--- container digests"
for ref in alpine:3.22 nginx:1.28-alpine; do
  docker pull -q "$ref" && docker image inspect --format '{{index .RepoDigests 0}}' "$ref"
done
docker version --format 'server {{.Server.Version}} api {{.Server.APIVersion}} min {{.Server.MinAPIVersion}}'
curl -s --unix-socket /var/run/docker.sock http://localhost/version | head -c 400; echo
