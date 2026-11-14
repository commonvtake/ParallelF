package ipam

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

func TestValidateCIDR(t *testing.T) {
	valid := []string{"10.20.1.0/24", "10.0.0.0/16", "10.254.255.224/27", " 10.66.0.0/24 "}
	for _, raw := range valid {
		if _, err := ValidateCIDR(raw); err != nil {
			t.Errorf("ValidateCIDR(%q) = %v, want ok", raw, err)
		}
	}

	invalid := map[string]string{
		"":                "CIDR notation",
		"10.20.1.0":       "CIDR notation",
		"fd00::/64":       "IPv4",
		"10.20.1.5/24":    "host bits",
		"10.0.0.0/8":      "between /16 and /27",
		"10.20.1.0/28":    "between /16 and /27",
		"192.168.1.0/24":  "inside 10.0.0.0/8",
		"172.17.0.0/16":   "inside 10.0.0.0/8",
		"10.255.0.0/24":   "reserved for the VPN",
		"10.255.128.0/17": "reserved for the VPN",
	}
	for raw, want := range invalid {
		_, err := ValidateCIDR(raw)
		if err == nil || (!strings.Contains(err.Error(), want) && !(want == "IPv4" && strings.Contains(err.Error(), "IPv4"))) {
			t.Errorf("ValidateCIDR(%q) = %v, want error containing %q", raw, err, want)
		}
	}
}

func TestLayoutOfANATNetwork(t *testing.T) {
	p := netip.MustParsePrefix("10.20.1.0/24")

	gw, ok := Gateway(p, KindNAT)
	if !ok || gw.String() != "10.20.1.1" {
		t.Errorf("Gateway = %v %v", gw, ok)
	}
	first, last := AssignableRange(p, KindNAT)
	if first.String() != "10.20.1.2" || last.String() != "10.20.1.248" {
		t.Errorf("AssignableRange = %v-%v", first, last)
	}
	s, e, ok := DHCPSpare(p, KindNAT)
	if !ok || s.String() != "10.20.1.249" || e.String() != "10.20.1.254" {
		t.Errorf("DHCPSpare = %v-%v %v", s, e, ok)
	}
	if got := Capacity(p, KindNAT); got != 247 {
		t.Errorf("Capacity = %d, want 247", got)
	}
}

func TestLabNetworksHaveNoGatewayOrDHCP(t *testing.T) {
	p := netip.MustParsePrefix("10.66.0.0/27")

	if _, ok := Gateway(p, KindLab); ok {
		t.Error("lab network has a gateway")
	}
	if _, _, ok := DHCPSpare(p, KindLab); ok {
		t.Error("lab network has a DHCP pool")
	}
	first, last := AssignableRange(p, KindLab)
	if first.String() != "10.66.0.2" || last.String() != "10.66.0.30" {
		t.Errorf("AssignableRange = %v-%v", first, last)
	}
	if got := Capacity(p, KindLab); got != 29 {
		t.Errorf("Capacity = %d, want 29", got)
	}
}

func TestNextFreeSkipsUsedAddressesAndReportsExhaustion(t *testing.T) {
	p := netip.MustParsePrefix("10.30.0.0/27") // nat: .2 - .24 assignable
	used := map[netip.Addr]bool{
		netip.MustParseAddr("10.30.0.2"): true,
		netip.MustParseAddr("10.30.0.3"): true,
		netip.MustParseAddr("10.30.0.5"): true,
	}
	got, err := NextFree(p, KindNAT, used)
	if err != nil || got.String() != "10.30.0.4" {
		t.Fatalf("NextFree = %v, %v", got, err)
	}

	for a := netip.MustParseAddr("10.30.0.2"); a.Compare(netip.MustParseAddr("10.30.0.24")) <= 0; a = a.Next() {
		used[a] = true
	}
	if _, err := NextFree(p, KindNAT, used); err != ErrExhausted {
		t.Fatalf("NextFree on a full network = %v, want ErrExhausted", err)
	}
}

func TestRandomMAC(t *testing.T) {
	pattern := regexp.MustCompile(`^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)
	seen := map[string]bool{}
	for range 50 {
		mac := RandomMAC()
		if !pattern.MatchString(mac) {
			t.Fatalf("RandomMAC = %q", mac)
		}
		seen[mac] = true
	}
	if len(seen) < 45 {
		t.Errorf("only %d distinct MACs in 50 draws", len(seen))
	}
}

func TestBridgeNameFitsInterfaceNameLimit(t *testing.T) {
	got := BridgeName("01937c1e-6f1a-7b4e-9a51-0c9f5d2b8e11")
	if got != "pfbr-5d2b8e11" {
		t.Errorf("BridgeName = %q", got)
	}
	if len(got) > 15 {
		t.Errorf("bridge name %q is longer than 15 bytes", got)
	}
}
