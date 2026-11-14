// Package cloudinit renders the NoCloud seed documents for a VM.
//
// The output is a pure function of the workload, its template and its
// network, so the same inputs always produce byte-identical seeds: that is
// what makes provisioning reproducible.
package cloudinit

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

// Input is everything the seed depends on.
type Input struct {
	WorkloadID string
	Hostname   string
	// TemplateConfig is the template's cloud-config document. Keys set by
	// the platform (hostname, ssh_authorized_keys) override it.
	TemplateConfig    map[string]any
	SSHAuthorizedKeys []string
	// StaticNetwork makes the guest configure its address itself instead
	// of using DHCP. Required on lab networks, which have no DHCP server.
	StaticNetwork bool
	MAC           string
	IP            netip.Addr
	Prefix        netip.Prefix
	Gateway       netip.Addr // invalid on lab networks
}

// Render returns the meta-data, user-data and (for static addressing)
// network-config documents. JSON is valid YAML, and encoding/json writes
// map keys in sorted order, so the documents are deterministic.
func Render(in Input) (cloudagent.CloudInit, error) {
	meta, err := json.Marshal(map[string]string{
		"instance-id":    in.WorkloadID,
		"local-hostname": in.Hostname,
	})
	if err != nil {
		return cloudagent.CloudInit{}, err
	}

	config := make(map[string]any, len(in.TemplateConfig)+3)
	for k, v := range in.TemplateConfig {
		config[k] = v
	}
	config["hostname"] = in.Hostname
	config["preserve_hostname"] = false
	if len(in.SSHAuthorizedKeys) > 0 {
		keys := append([]string(nil), in.SSHAuthorizedKeys...)
		sort.Strings(keys)
		config["ssh_authorized_keys"] = keys
	}
	user, err := json.Marshal(config)
	if err != nil {
		return cloudagent.CloudInit{}, fmt.Errorf("template cloud-config: %w", err)
	}

	out := cloudagent.CloudInit{
		MetaData: string(meta) + "\n",
		UserData: "#cloud-config\n" + string(user) + "\n",
	}
	if in.StaticNetwork {
		network, err := networkConfig(in)
		if err != nil {
			return cloudagent.CloudInit{}, err
		}
		out.NetworkConfig = network
	}
	return out, nil
}

// networkConfig renders a version 2 (netplan-style) network configuration
// that matches the interface by MAC address.
func networkConfig(in Input) (string, error) {
	if !in.IP.IsValid() || !in.Prefix.IsValid() {
		return "", fmt.Errorf("static network needs an address and a prefix")
	}
	eth := map[string]any{
		"match":     map[string]string{"macaddress": in.MAC},
		"set-name":  "eth0",
		"dhcp4":     false,
		"addresses": []string{netip.PrefixFrom(in.IP, in.Prefix.Bits()).String()},
	}
	if in.Gateway.IsValid() {
		eth["routes"] = []map[string]string{{"to": "default", "via": in.Gateway.String()}}
		eth["nameservers"] = map[string][]string{"addresses": {in.Gateway.String()}}
	}
	doc, err := json.Marshal(map[string]any{
		"version":   2,
		"ethernets": map[string]any{"eth0": eth},
	})
	if err != nil {
		return "", err
	}
	return string(doc) + "\n", nil
}
