package cloudinit

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func input() Input {
	return Input{
		WorkloadID:        "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f",
		Hostname:          "web-1",
		TemplateConfig:    map[string]any{"package_update": false, "hostname": "template-value"},
		SSHAuthorizedKeys: []string{"ssh-ed25519 BBBB b", "ssh-ed25519 AAAA a"},
		MAC:               "52:54:00:aa:bb:01",
		IP:                netip.MustParseAddr("10.20.1.5"),
		Prefix:            netip.MustParsePrefix("10.20.1.0/24"),
		Gateway:           netip.MustParseAddr("10.20.1.1"),
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, err := Render(input())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(input())
	if a != b {
		t.Fatalf("two renders differ:\n%+v\n%+v", a, b)
	}
}

func TestUserDataMergesTemplateAndPlatformKeys(t *testing.T) {
	out, err := Render(input())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.UserData, "#cloud-config\n") {
		t.Fatalf("user-data must start with #cloud-config: %q", out.UserData)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(out.UserData, "#cloud-config\n")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["hostname"] != "web-1" {
		t.Errorf("platform hostname must override the template: %v", doc["hostname"])
	}
	if doc["package_update"] != false {
		t.Errorf("template keys must be kept: %v", doc)
	}
	keys := doc["ssh_authorized_keys"].([]any)
	if len(keys) != 2 || keys[0] != "ssh-ed25519 AAAA a" {
		t.Errorf("keys must be sorted: %v", keys)
	}
	if out.NetworkConfig != "" {
		t.Errorf("DHCP templates get no network-config")
	}
	if out.MetaData != `{"instance-id":"0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f","local-hostname":"web-1"}`+"\n" {
		t.Errorf("meta-data: %q", out.MetaData)
	}
}

func TestStaticNetworkConfig(t *testing.T) {
	in := input()
	in.StaticNetwork = true
	out, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ethernets":{"eth0":{"addresses":["10.20.1.5/24"],"dhcp4":false,"match":{"macaddress":"52:54:00:aa:bb:01"},` +
		`"nameservers":{"addresses":["10.20.1.1"]},"routes":[{"to":"default","via":"10.20.1.1"}],"set-name":"eth0"}},"version":2}` + "\n"
	if out.NetworkConfig != want {
		t.Fatalf("network-config:\n got %s\nwant %s", out.NetworkConfig, want)
	}
}

func TestStaticNetworkWithoutGatewayHasNoRoute(t *testing.T) {
	in := input()
	in.StaticNetwork = true
	in.Gateway = netip.Addr{}
	out, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.NetworkConfig, "routes") || strings.Contains(out.NetworkConfig, "nameservers") {
		t.Fatalf("lab networks have no gateway: %s", out.NetworkConfig)
	}
}
