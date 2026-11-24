package nft

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func desired() vpnagent.SyncResponse {
	return vpnagent.SyncResponse{
		Revision: 7,
		Active: []vpnagent.Activation{
			{Address: "10.255.0.10", ExpiresAt: now.Add(time.Hour)},
			{Address: "10.255.0.11", ExpiresAt: now.Add(-time.Minute)}, // expired: left out
		},
		Policies: []vpnagent.Policy{
			{Name: "web", Priority: 20, Action: "allow", Sources: []string{"10.255.0.10", "10.255.0.11"},
				Destinations: []string{"10.255.0.1/32", "10.20.1.5/24"}, Protocol: "tcp", Ports: []string{"443", "8000-8100", "80"}},
			{Name: "block-ssh", Priority: 10, Action: "deny", Sources: []string{"10.255.0.10"},
				Destinations: []string{"10.255.0.1/32"}, Protocol: "tcp", Ports: []string{"22"}},
			{Name: "ping", Priority: 30, Action: "allow", Sources: nil, Destinations: []string{"10.255.0.1/32"}, Protocol: "icmp"},
		},
	}
}

func TestRenderOrdersPoliciesAndDropsExpiredActivations(t *testing.T) {
	r, err := Render("wg-pf0", desired(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Active) != 1 || r.Active["10.255.0.10"] != time.Hour {
		t.Fatalf("active = %v", r.Active)
	}
	s := r.Structure
	deny := strings.Index(s, `tcp dport { 22 } counter drop comment "policy 0"`)
	allow := strings.Index(s, `tcp dport { 443, 8000-8100, 80 } counter accept comment "policy 1"`)
	icmp := strings.Index(s, `ip protocol icmp counter accept comment "policy 2"`)
	if deny < 0 || allow < 0 || icmp < 0 || deny > allow || allow > icmp {
		t.Fatalf("policies not rendered in priority order:\n%s", s)
	}
	gate := strings.Index(s, `iifname "wg-pf0" ip saddr != @active_peers counter drop`)
	established := strings.Index(s, `iifname "wg-pf0" ct state established,related accept`)
	if gate < 0 || established < 0 || gate > established {
		t.Fatalf("the activation check must precede accepting established traffic:\n%s", s)
	}
	if !strings.Contains(s, "set d1 { type ipv4_addr; flags interval; auto-merge; elements = { 10.20.1.0/24, 10.255.0.1/32 }; }") {
		t.Fatalf("destination set not normalised:\n%s", s)
	}
	if !strings.Contains(s, "set s2 { type ipv4_addr; }") {
		t.Fatalf("a policy without sources must render an empty set:\n%s", s)
	}
	if strings.Count(s, `counter drop comment "default deny"`) != 2 {
		t.Fatalf("both chains must end in a default deny:\n%s", s)
	}
	script := r.Script()
	if !strings.HasPrefix(script, "table inet parallelf_vpn {}\ndelete table inet parallelf_vpn\n") ||
		!strings.HasSuffix(script, "add element inet parallelf_vpn active_peers { 10.255.0.10 timeout 3600s }\n") {
		t.Fatalf("script:\n%s", script)
	}
	if path := os.Getenv("PF_NFT_SCRIPT_OUT"); path != "" {
		_ = os.WriteFile(path, []byte(script), 0o600) // for `nft -c -f` in CI
	}
}

func TestStructureIgnoresActivations(t *testing.T) {
	a, _ := Render("wg-pf0", desired(), now)
	d := desired()
	d.Active = nil
	b, _ := Render("wg-pf0", d, now)
	if a.Hash != b.Hash {
		t.Fatal("activations must not change the structure hash")
	}
	d.Policies[0].Ports = []string{"443"}
	c, _ := Render("wg-pf0", d, now)
	if c.Hash == a.Hash {
		t.Fatal("a policy change must change the structure hash")
	}
}

func TestRenderRejectsAnythingThatIsNotStructured(t *testing.T) {
	bad := []func(*vpnagent.SyncResponse){
		func(s *vpnagent.SyncResponse) { s.Active[0].Address = "10.255.0.10; flush ruleset" },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Sources = []string{"2001:db8::1"} },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Destinations = []string{"10.0.0.0/33"} },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Ports = []string{"0"} },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Ports = []string{"90-80"} },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Ports = []string{"22 } accept"} },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Action = "accept" },
		func(s *vpnagent.SyncResponse) { s.Policies[0].Protocol = "sctp" },
		func(s *vpnagent.SyncResponse) { s.Policies[2].Ports = []string{"1"} },
	}
	for i, mutate := range bad {
		d := desired()
		mutate(&d)
		if _, err := Render("wg-pf0", d, now); err == nil {
			t.Errorf("case %d: rendered invalid input", i)
		}
	}
	if _, err := Render(`wg"x`, desired(), now); err == nil {
		t.Error("rendered an invalid interface name")
	}
}

func TestParseActive(t *testing.T) {
	out := []byte(`{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"set": {"family": "inet", "name": "active_peers",
	  "table": "parallelf_vpn", "type": "ipv4_addr", "flags": ["timeout"],
	  "elem": [{"elem": {"val": "10.255.0.10", "timeout": 3600, "expires": 3541}}, "10.255.0.12"]}}]}`)
	got, err := ParseActive(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["10.255.0.10"] != 3541*time.Second || got["10.255.0.12"] != 0 {
		t.Fatalf("got %v", got)
	}
}

type call struct {
	args  string
	stdin string
}

type fakeRunner struct {
	calls  []call
	active string // JSON for `nft -j list set`
	exists bool
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call{line, string(stdin)})
	switch {
	case strings.HasPrefix(line, "nft list table"):
		if !f.exists {
			return nil, os.ErrNotExist
		}
	case strings.HasPrefix(line, "nft -j list set"):
		return []byte(f.active), nil
	case line == "nft -f -":
		f.exists = true
	}
	return nil, nil
}

func TestApplyReplacesOnlyWhenTheStructureChanges(t *testing.T) {
	run := &fakeRunner{}
	a := &Applier{Run: run}
	r, _ := Render("wg-pf0", desired(), now)
	if replaced, err := a.Apply(context.Background(), r); err != nil || !replaced {
		t.Fatalf("first apply: %v %v", replaced, err)
	}

	// Same structure; the kernel has one stale element and a nearly equal
	// timer for the desired one: only the stale element goes.
	run.calls = nil
	run.active = `{"nftables": [{"set": {"elem": [{"elem": {"val": "10.255.0.10", "expires": 3598}}, {"elem": {"val": "10.255.0.99", "expires": 10}}]}}]}`
	if replaced, err := a.Apply(context.Background(), r); err != nil || replaced {
		t.Fatalf("second apply: %v %v", replaced, err)
	}
	last := run.calls[len(run.calls)-1]
	if last.args != "nft -f -" || last.stdin != "delete element inet parallelf_vpn active_peers { 10.255.0.99 }\n" {
		t.Fatalf("incremental update: %+v", run.calls)
	}

	// An extension re-adds the element with the new timeout.
	run.calls = nil
	run.active = `{"nftables": [{"set": {"elem": [{"elem": {"val": "10.255.0.10", "expires": 60}}]}}]}`
	if _, err := a.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	last = run.calls[len(run.calls)-1]
	want := "delete element inet parallelf_vpn active_peers { 10.255.0.10 }\nadd element inet parallelf_vpn active_peers { 10.255.0.10 timeout 3600s }\n"
	if last.stdin != want {
		t.Fatalf("extension: %q", last.stdin)
	}

	// Nothing to do: no nft transaction at all.
	run.calls = nil
	run.active = `{"nftables": [{"set": {"elem": [{"elem": {"val": "10.255.0.10", "expires": 3600}}]}}]}`
	_, _ = a.Apply(context.Background(), r)
	for _, c := range run.calls {
		if c.args == "nft -f -" {
			t.Fatalf("unexpected transaction %q", c.stdin)
		}
	}
}
