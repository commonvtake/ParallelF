package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/auditlog"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
	"github.com/commonvtake/parallelf/services/vpn/internal/events"
	"github.com/commonvtake/parallelf/services/vpn/internal/pskcrypt"
)

var user = domain.Actor{Type: "user", ID: "sub-test", Name: "tester"}

func openStore(t *testing.T) *Postgres {
	t.Helper()
	url := os.Getenv("PF_TEST_VPN_DATABASE_URL")
	if url == "" {
		t.Skip("PF_TEST_VPN_DATABASE_URL is not set; skipping PostgreSQL integration test")
	}
	box, err := pskcrypt.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), url, Options{
		Encoder: events.NewEncoder(ids.NewV7, time.Now), PSK: box, NewID: ids.NewV7, Now: time.Now,
		Tunnel: netip.MustParsePrefix("10.255.0.0/22"), DeviceTTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func newKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// gateway registers (or re-registers) the shared test gateway.
func gateway(t *testing.T, s *Postgres) (domain.Gateway, string) {
	t.Helper()
	token := ids.NewV7()
	g, err := s.RegisterGateway(context.Background(), domain.GatewayRegistration{
		RegisterRequest: vpnagent.RegisterRequest{Name: "test-gateway", AgentVersion: "test", PublicKey: newKey(t), Endpoint: "192.0.2.1:51820", ListenPort: 51820},
		TokenHash:       []byte(token)[:32],
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, token
}

func auditFilter(id string) auditlog.Filter {
	return auditlog.Filter{ResourceType: "device", ResourceID: id, Limit: 50}
}

func owner(groups ...string) domain.Owner {
	return domain.Owner{Subject: "sub-" + ids.NewV7()[:8], Name: "tester", Groups: groups}
}

func peerFor(resp vpnagent.SyncResponse, id string) (vpnagent.Peer, bool) {
	for _, p := range resp.Peers {
		if p.DeviceID == id {
			return p, true
		}
	}
	return vpnagent.Peer{}, false
}

func activeFor(resp vpnagent.SyncResponse, address string) bool {
	for _, a := range resp.Active {
		if a.Address == address {
			return true
		}
	}
	return false
}

func TestDeviceLifecycleAndDesiredState(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	gw, _ := gateway(t, s)
	o := owner("admin")

	rev0, _ := s.Revision(ctx)
	changed := s.Changed()
	key := newKey(t)
	d, psk, err := s.CreateDevice(ctx, domain.DeviceInput{Name: "laptop", PublicKey: key, PresharedKey: true}, o, user)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != domain.StatePending || !d.PresharedKey || psk == "" || d.Active {
		t.Fatalf("created %+v", d)
	}
	select {
	case <-changed:
	default:
		t.Fatal("creating a device must wake waiting agents")
	}
	if rev, _ := s.Revision(ctx); rev <= rev0 {
		t.Fatal("revision not bumped")
	}

	// The same key cannot be enrolled twice, nor the same name for one owner.
	if _, _, err := s.CreateDevice(ctx, domain.DeviceInput{Name: "other", PublicKey: key}, owner(), user); !errors.Is(err, domain.ErrKeyTaken) {
		t.Fatalf("duplicate key: %v", err)
	}
	if _, _, err := s.CreateDevice(ctx, domain.DeviceInput{Name: "laptop", PublicKey: newKey(t)}, o, user); !errors.Is(err, domain.ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}

	desired, err := s.DesiredState(ctx, gw)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := peerFor(desired, d.ID)
	if !ok || peer.PresharedKey != psk || peer.Address != d.Address || activeFor(desired, d.Address) {
		t.Fatalf("desired peer %+v ok=%v", peer, ok)
	}
	if desired.Interface.Address != "10.255.0.1/22" || desired.Interface.ListenPort != 51820 {
		t.Fatalf("interface %+v", desired.Interface)
	}

	// The gateway reports the peer: enrolled, with statistics.
	if err := s.Sync(ctx, gw, vpnagent.SyncRequest{Revision: desired.Revision, Peers: []vpnagent.PeerStatus{
		{PublicKey: key, LatestHandshake: time.Now().Unix(), RxBytes: 100, TxBytes: 200, Endpoint: "198.51.100.7:4000"},
	}}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.GetDevice(ctx, d.ID)
	if d.State != domain.StateEnrolled || d.Connection != domain.ConnOnline || d.RxBytes != 100 {
		t.Fatalf("after sync %+v", d)
	}

	// Activation appears in the desired state with its expiry.
	until := time.Now().Add(time.Hour).Truncate(time.Second)
	if d, err = s.Activate(ctx, d.ID, until, user); err != nil || !d.Active {
		t.Fatalf("activate %+v %v", d, err)
	}
	desired, _ = s.DesiredState(ctx, gw)
	if !activeFor(desired, d.Address) {
		t.Fatal("activation missing from desired state")
	}
	if d, err = s.Deactivate(ctx, d.ID, user); err != nil || d.Active {
		t.Fatalf("deactivate %+v %v", d, err)
	}
	if _, err := s.Deactivate(ctx, d.ID, user); !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("deactivating twice: %v", err)
	}

	// Revocation removes the peer and frees its address and key.
	if d, err = s.Revoke(ctx, d.ID, user); err != nil || d.State != domain.StateRevoked || d.EndedAt == nil {
		t.Fatalf("revoke %+v %v", d, err)
	}
	desired, _ = s.DesiredState(ctx, gw)
	if _, ok := peerFor(desired, d.ID); ok {
		t.Fatal("a revoked device must leave the desired state")
	}
	again, _, err := s.CreateDevice(ctx, domain.DeviceInput{Name: "laptop", PublicKey: key}, o, user)
	if err != nil || again.Address != d.Address {
		t.Fatalf("key and address reuse after revocation: %+v %v", again, err)
	}
	_, _ = s.Revoke(ctx, again.ID, user)

	entries, err := s.ListAudit(ctx, auditFilter(d.ID))
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	if strings.Join(actions, ",") != "vpn.devices.revoke,vpn.devices.deactivate,vpn.devices.activate,vpn.devices.create" {
		t.Fatalf("audit %v", actions)
	}
	if v, err := s.VerifyAudit(ctx); err != nil || !v.Valid {
		t.Fatalf("audit chain %+v %v", v, err)
	}
}

func TestPoliciesCompileToDeviceAddresses(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	gw, _ := gateway(t, s)
	group := "grp" + strings.ToLower(ids.NewV7()[:6])
	d, _, err := s.CreateDevice(ctx, domain.DeviceInput{Name: "box", PublicKey: newKey(t)}, owner(group), user)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.Revoke(ctx, d.ID, user) }()

	in := domain.PolicyInput{Name: "p-" + strings.ToLower(ids.NewV7()[:6]), Priority: 5, Action: "allow", Groups: []string{group},
		Destinations: []string{"10.20.9.0/24", "platform"}, Protocol: "tcp", Ports: []string{"22"}}
	if err := in.Validate(netip.MustParsePrefix("10.255.0.0/22")); err != nil {
		t.Fatal(err)
	}
	p, err := s.CreatePolicy(ctx, in, user)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.DeletePolicy(ctx, p.ID, user) }()
	if _, err := s.CreatePolicy(ctx, in, user); !errors.Is(err, domain.ErrNameTaken) {
		t.Fatalf("duplicate policy: %v", err)
	}

	desired, _ := s.DesiredState(ctx, gw)
	found := false
	for _, cp := range desired.Policies {
		if cp.Name == p.Name {
			found = true
			if strings.Join(cp.Sources, ",") != d.Address || strings.Join(cp.Destinations, ",") != "10.20.9.0/24,10.255.0.1/32" {
				t.Fatalf("compiled %+v", cp)
			}
		}
	}
	if !found || !desired.Interface.Forwarding {
		t.Fatalf("policy not compiled (forwarding %v)", desired.Interface.Forwarding)
	}
	cfg, err := s.DeviceConfig(ctx, d)
	if err != nil || strings.Join(cfg.AllowedIPs, ",") != "10.255.0.0/22,10.20.9.0/24" || cfg.GatewayPublicKey == "" {
		t.Fatalf("client config %+v %v", cfg, err)
	}
}

func TestExpiryAndSilentGateways(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	gw, _ := gateway(t, s)
	d, _, err := s.CreateDevice(ctx, domain.DeviceInput{Name: "old", PublicKey: newKey(t)}, owner(), user)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireDevices(ctx, d.ExpiresAt.Add(time.Second)); err != nil || n < 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if got, _ := s.GetDevice(ctx, d.ID); got.State != domain.StateExpired {
		t.Fatalf("state %s", got.State)
	}
	changed, err := s.MarkSilentGateways(ctx, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, g := range changed {
		marked = marked || g.ID == gw.ID
	}
	if !marked {
		t.Fatal("gateway not marked NOT_READY")
	}
	if err := s.Sync(ctx, gw, vpnagent.SyncRequest{}); err != nil {
		t.Fatal(err)
	}
	gws, _ := s.ListGateways(ctx)
	for _, g := range gws {
		if g.ID == gw.ID && g.Status != domain.GatewayReady {
			t.Fatal("a reporting gateway must be READY again")
		}
	}
}
