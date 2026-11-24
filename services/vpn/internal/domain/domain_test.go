package domain

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
)

var tunnel = netip.MustParsePrefix("10.255.0.0/22")

func TestValidKey(t *testing.T) {
	for key, want := range map[string]bool{
		"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=": true,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=": false, // all zero
		"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg":  false, // unpadded
		"short": false,
	} {
		if got := ValidKey(key); got != want {
			t.Errorf("ValidKey(%q) = %v", key, got)
		}
	}
}

func TestAddresses(t *testing.T) {
	if got := GatewayAddress(tunnel); got.String() != "10.255.0.1" {
		t.Fatalf("gateway %s", got)
	}
	used := map[netip.Addr]bool{netip.MustParseAddr("10.255.0.10"): true}
	a, err := NextAddress(tunnel, used)
	if err != nil || a.String() != "10.255.0.11" {
		t.Fatalf("next %s %v", a, err)
	}
	small := netip.MustParsePrefix("10.255.0.0/28") // .10 to .14 usable
	full := map[netip.Addr]bool{}
	for i := 10; i <= 14; i++ {
		full[netip.AddrFrom4([4]byte{10, 255, 0, byte(i)})] = true
	}
	if _, err := NextAddress(small, full); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("exhausted: %v", err)
	}
}

func TestConnection(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	if Connection(nil, now) != ConnOffline || Connection(at(time.Minute), now) != ConnOnline ||
		Connection(at(10*time.Minute), now) != ConnIdle || Connection(at(time.Hour), now) != ConnOffline {
		t.Fatal("connection thresholds")
	}
	until := now.Add(time.Minute)
	d := Device{State: StateEnrolled, ActiveUntil: &until}.Derive(now)
	if !d.Active {
		t.Fatal("active")
	}
	d.State = StateRevoked
	if d.Derive(now).Active {
		t.Fatal("a revoked device is never active")
	}
}

func TestPolicyValidation(t *testing.T) {
	in := PolicyInput{Name: "web", Priority: 10, Action: "allow", Groups: []string{"ops", "admin", "ops"},
		Destinations: []string{"10.20.1.7/24", "platform"}, Protocol: "tcp", Ports: []string{"443", "8000-8100"}}
	if err := in.Validate(tunnel); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.Groups, []string{"admin", "ops"}) || !reflect.DeepEqual(in.Destinations, []string{"10.20.1.0/24", "platform"}) {
		t.Fatalf("normalised %+v", in)
	}
	bad := PolicyInput{Name: "X", Priority: 0, Action: "accept", Destinations: []string{"10.255.1.0/24", "example.com"},
		Protocol: "icmp", Ports: []string{"22"}}
	err := bad.Validate(tunnel)
	var v *ValidationError
	if !errors.As(err, &v) {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, e := range v.Errors {
		fields[e.Field] = true
	}
	for _, f := range []string{"name", "priority", "action", "groups", "destinations", "ports"} {
		if !fields[f] {
			t.Errorf("no error for %s: %+v", f, v.Errors)
		}
	}
}

func TestCompilePolicies(t *testing.T) {
	devices := []Device{
		{Address: "10.255.0.10", Groups: []string{"admin"}, State: StateEnrolled},
		{Address: "10.255.0.11", Groups: []string{"ops"}, State: StatePending},
		{Address: "10.255.0.12", Groups: []string{"admin"}, State: StateRevoked},
	}
	policies := []Policy{
		{Name: "net", Priority: 20, Action: "allow", Groups: []string{"admin", "ops"}, Destinations: []string{"10.20.1.0/24"}, Protocol: "tcp", Ports: []string{"22"}},
		{Name: "platform", Priority: 10, Action: "allow", Groups: []string{"admin"}, Destinations: []string{"platform"}, Protocol: "icmp"},
	}
	got, forwarding := CompilePolicies(policies, devices, netip.MustParseAddr("10.255.0.1"))
	want := []vpnagent.Policy{
		{Name: "platform", Priority: 10, Action: "allow", Sources: []string{"10.255.0.10"}, Destinations: []string{"10.255.0.1/32"}, Protocol: "icmp", Ports: nil},
		{Name: "net", Priority: 20, Action: "allow", Sources: []string{"10.255.0.10", "10.255.0.11"}, Destinations: []string{"10.20.1.0/24"}, Protocol: "tcp", Ports: []string{"22"}},
	}
	if !reflect.DeepEqual(got, want) || !forwarding {
		t.Fatalf("got %+v forwarding %v", got, forwarding)
	}
	allowed := ClientAllowedIPs(tunnel, []string{"ops"}, policies)
	if !reflect.DeepEqual(allowed, []string{"10.255.0.0/22", "10.20.1.0/24"}) {
		t.Fatalf("allowed %v", allowed)
	}
}
