package libvirt

import (
	"encoding/xml"
	"fmt"
	"net/netip"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

// Domain and network documents are built from typed structs and encoded by
// encoding/xml, never by string templates, so no value from the API can
// change the document's structure.

type domainXML struct {
	XMLName  xml.Name   `xml:"domain"`
	Type     string     `xml:"type,attr"`
	Name     string     `xml:"name"`
	UUID     string     `xml:"uuid"`
	Title    string     `xml:"title"`
	Memory   sizedValue `xml:"memory"`
	VCPU     int        `xml:"vcpu"`
	OS       osXML      `xml:"os"`
	Features struct {
		ACPI struct{} `xml:"acpi"`
		APIC struct{} `xml:"apic"`
	} `xml:"features"`
	CPU struct {
		Mode string `xml:"mode,attr"`
	} `xml:"cpu"`
	Clock struct {
		Offset string `xml:"offset,attr"`
	} `xml:"clock"`
	OnPoweroff string     `xml:"on_poweroff"`
	OnReboot   string     `xml:"on_reboot"`
	OnCrash    string     `xml:"on_crash"`
	Devices    devicesXML `xml:"devices"`
}

type sizedValue struct {
	Unit  string `xml:"unit,attr"`
	Value int    `xml:",chardata"`
}

type osXML struct {
	Type struct {
		Arch    string `xml:"arch,attr"`
		Machine string `xml:"machine,attr"`
		Value   string `xml:",chardata"`
	} `xml:"type"`
	Boot struct {
		Dev string `xml:"dev,attr"`
	} `xml:"boot"`
}

type devicesXML struct {
	Disks      []diskXML  `xml:"disk"`
	Interfaces []ifaceXML `xml:"interface"`
	Serial     serialXML  `xml:"serial"`
	Console    consoleXML `xml:"console"`
	RNG        rngXML     `xml:"rng"`
	Balloon    memballoon `xml:"memballoon"`
}

type diskXML struct {
	Type   string `xml:"type,attr"`
	Device string `xml:"device,attr"`
	Driver struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"driver"`
	Source struct {
		File string `xml:"file,attr"`
	} `xml:"source"`
	Target struct {
		Dev string `xml:"dev,attr"`
		Bus string `xml:"bus,attr"`
	} `xml:"target"`
	ReadOnly *struct{} `xml:"readonly"`
}

type ifaceXML struct {
	Type string `xml:"type,attr"`
	MAC  struct {
		Address string `xml:"address,attr"`
	} `xml:"mac"`
	Source struct {
		Network string `xml:"network,attr"`
	} `xml:"source"`
	Model struct {
		Type string `xml:"type,attr"`
	} `xml:"model"`
}

type serialXML struct {
	Type string `xml:"type,attr"`
	Log  struct {
		File   string `xml:"file,attr"`
		Append string `xml:"append,attr"`
	} `xml:"log"`
	Target struct {
		Port int `xml:"port,attr"`
	} `xml:"target"`
}

type consoleXML struct {
	Type   string `xml:"type,attr"`
	Target struct {
		Type string `xml:"type,attr"`
		Port int    `xml:"port,attr"`
	} `xml:"target"`
}

type rngXML struct {
	Model   string `xml:"model,attr"`
	Backend struct {
		Model string `xml:"model,attr"`
		Value string `xml:",chardata"`
	} `xml:"backend"`
}

type memballoon struct {
	Model string `xml:"model,attr"`
	Stats struct {
		Period int `xml:"period,attr"`
	} `xml:"stats"`
}

// DomainName is the libvirt name of a workload's VM.
func DomainName(workloadID string) string { return "pf-" + workloadID }

// domainDocument renders the VM definition. The layout (i440fx machine,
// virtio disk and NIC, IDE CD-ROM seed, serial log) was verified to boot
// CirrOS and Ubuntu cloud images under nested KVM.
func domainDocument(w cloudagent.DesiredWorkload, bridge, disk, seed, consoleLog string) ([]byte, error) {
	d := domainXML{
		Type: "kvm", Name: DomainName(w.ID), UUID: w.ID, Title: w.Name,
		Memory: sizedValue{Unit: "MiB", Value: w.MemoryMiB}, VCPU: w.VCPUs,
		OnPoweroff: "destroy", OnReboot: "restart", OnCrash: "destroy",
	}
	d.OS.Type.Arch, d.OS.Type.Machine, d.OS.Type.Value = "x86_64", "pc", "hvm"
	d.OS.Boot.Dev = "hd"
	d.CPU.Mode = "host-passthrough"
	d.Clock.Offset = "utc"

	var root diskXML
	root.Type, root.Device = "file", "disk"
	root.Driver.Name, root.Driver.Type = "qemu", "qcow2"
	root.Source.File = disk
	root.Target.Dev, root.Target.Bus = "vda", "virtio"

	var cd diskXML
	cd.Type, cd.Device = "file", "cdrom"
	cd.Driver.Name, cd.Driver.Type = "qemu", "raw"
	cd.Source.File = seed
	cd.Target.Dev, cd.Target.Bus = "hdc", "ide"
	cd.ReadOnly = &struct{}{}
	d.Devices.Disks = []diskXML{root, cd}

	var nic ifaceXML
	nic.Type = "network"
	nic.MAC.Address = w.MAC
	nic.Source.Network = bridge
	nic.Model.Type = "virtio"
	d.Devices.Interfaces = []ifaceXML{nic}

	d.Devices.Serial.Type = "pty"
	d.Devices.Serial.Log.File, d.Devices.Serial.Log.Append = consoleLog, "off"
	d.Devices.Console.Type = "pty"
	d.Devices.Console.Target.Type = "serial"
	d.Devices.RNG.Model = "virtio"
	d.Devices.RNG.Backend.Model, d.Devices.RNG.Backend.Value = "random", "/dev/urandom"
	d.Devices.Balloon.Model = "virtio"
	d.Devices.Balloon.Stats.Period = 10

	return xml.MarshalIndent(d, "", "  ")
}

type networkXML struct {
	XMLName xml.Name `xml:"network"`
	Name    string   `xml:"name"`
	Bridge  struct {
		Name  string `xml:"name,attr"`
		STP   string `xml:"stp,attr"`
		Delay string `xml:"delay,attr"`
	} `xml:"bridge"`
	Forward *forwardXML `xml:"forward"`
	IP      *networkIP  `xml:"ip"`
}

type forwardXML struct {
	Mode string `xml:"mode,attr"`
}

type networkIP struct {
	Address string   `xml:"address,attr"`
	Prefix  int      `xml:"prefix,attr"`
	DHCP    *dhcpXML `xml:"dhcp"`
}

type dhcpXML struct {
	Range *rangeXML  `xml:"range"`
	Hosts []dhcpHost `xml:"host"`
}

type rangeXML struct {
	Start string `xml:"start,attr"`
	End   string `xml:"end,attr"`
}

type dhcpHost struct {
	XMLName xml.Name `xml:"host"`
	MAC     string   `xml:"mac,attr"`
	Name    string   `xml:"name,attr,omitempty"`
	IP      string   `xml:"ip,attr"`
}

// networkDocument renders a network definition.
//
//	nat       bridge with the gateway address, DHCP, and NAT to the uplink
//	isolated  bridge with the gateway address and DHCP, no forwarding
//	lab       bridge only: the host has no address on it, there is no DHCP
//	          and libvirt installs no forwarding rules
func networkDocument(n cloudagent.DesiredNetwork) ([]byte, error) {
	doc := networkXML{Name: n.Bridge}
	doc.Bridge.Name, doc.Bridge.STP, doc.Bridge.Delay = n.Bridge, "on", "0"

	switch n.Kind {
	case cloudagent.NetworkLab:
	case cloudagent.NetworkNAT, cloudagent.NetworkIsolated:
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			return nil, fmt.Errorf("network %s: %w", n.ID, err)
		}
		ip := &networkIP{Address: n.Gateway, Prefix: prefix.Bits(), DHCP: &dhcpXML{}}
		if n.DHCPSpareStart != "" {
			ip.DHCP.Range = &rangeXML{Start: n.DHCPSpareStart, End: n.DHCPSpareEnd}
		}
		for _, r := range n.Reservations {
			ip.DHCP.Hosts = append(ip.DHCP.Hosts, dhcpHost{MAC: r.MAC, Name: r.Name, IP: r.IP})
		}
		doc.IP = ip
		if n.Kind == cloudagent.NetworkNAT {
			doc.Forward = &forwardXML{Mode: "nat"}
		}
	default:
		return nil, fmt.Errorf("network %s: unknown kind %q", n.ID, n.Kind)
	}
	return xml.MarshalIndent(doc, "", "  ")
}

// hostEntry renders one DHCP reservation for virsh net-update.
func hostEntry(r cloudagent.DHCPReservation) (string, error) {
	b, err := xml.Marshal(dhcpHost{MAC: r.MAC, Name: r.Name, IP: r.IP})
	return string(b), err
}

// parseReservations reads the DHCP host entries of a network definition.
func parseReservations(doc []byte) ([]cloudagent.DHCPReservation, error) {
	var n networkXML
	if err := xml.Unmarshal(doc, &n); err != nil {
		return nil, fmt.Errorf("parse network XML: %w", err)
	}
	var out []cloudagent.DHCPReservation
	if n.IP != nil && n.IP.DHCP != nil {
		for _, h := range n.IP.DHCP.Hosts {
			out = append(out, cloudagent.DHCPReservation{MAC: h.MAC, IP: h.IP, Name: h.Name})
		}
	}
	return out, nil
}
