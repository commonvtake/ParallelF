package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
)

type fakeProbe struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeProbe) Ping(_ context.Context, ip netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ping "+ip.String())
	return ip.String() == "10.255.0.1"
}

func (f *fakeProbe) Connect(_ context.Context, ip netip.Addr, port int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "tcp "+ip.String())
	return ip.String() == "10.255.0.1" && port == 8000
}

func TestHosts(t *testing.T) {
	if h := Hosts("10.255.0.0/30"); len(h) != 2 || h[0].String() != "10.255.0.1" {
		t.Fatalf("/30: %v", h)
	}
	if h := Hosts("10.255.0.5/32"); len(h) != 1 {
		t.Fatalf("/32: %v", h)
	}
}

func TestScopesAreVerifiedRunOnceAndOnlyProbeTheirRange(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	scope := ngsensor.Scope{ID: "s1", CIDRs: []string{"10.255.0.0/30"}, Techniques: []string{"icmp-echo", "tcp-connect"},
		Ports: []int{8000, 9000}, RatePPS: 100, IssuedAt: now, ValidUntil: now.Add(time.Hour)}
	good, _ := ngsensor.Sign(scope, priv)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := ngsensor.Sign(ngsensor.Scope{ID: "evil", CIDRs: []string{"10.0.0.0/24"}, Techniques: []string{"icmp-echo"}, RatePPS: 1, ValidUntil: now.Add(time.Hour)}, otherKey)

	probe := &fakeProbe{}
	r := &Runner{Key: pub, Probe: probe, Now: time.Now}
	run, refused := r.Pending([]ngsensor.SignedScope{good, forged})
	if len(run) != 1 || run[0].ID != "s1" || len(refused) != 1 {
		t.Fatalf("run %v refused %v", run, refused)
	}
	if again, refusedAgain := r.Pending([]ngsensor.SignedScope{good, forged}); len(again) != 0 || len(refusedAgain) != 0 {
		t.Fatal("a scope runs once and a refusal is reported once")
	}
	events := r.Run(context.Background(), run[0])
	if len(events) != 2 || events[0].Details["discovery.result"] != "up" || events[1].DstPort != 8000 {
		t.Fatalf("events %+v", events)
	}
	for _, c := range probe.calls {
		if c != "ping 10.255.0.1" && c != "ping 10.255.0.2" && c != "tcp 10.255.0.1" && c != "tcp 10.255.0.2" {
			t.Fatalf("probed outside the scope: %s", c)
		}
	}
	if len(probe.calls) != 6 {
		t.Fatalf("calls %v", probe.calls)
	}
}
