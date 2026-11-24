package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/nft"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/wg"
)

type recorder struct {
	steps   []string
	failFW  bool
	ruleset nft.Ruleset
}

func (r *recorder) EnsureInterface(context.Context, vpnagent.Interface) error {
	r.steps = append(r.steps, "interface")
	return nil
}

func (r *recorder) SyncPeers(context.Context, []vpnagent.Peer) (int, error) {
	r.steps = append(r.steps, "peers")
	return 1, nil
}

func (r *recorder) Peers(context.Context) ([]wg.Peer, error) {
	return []wg.Peer{{PublicKey: "k", Handshake: 5, Rx: 1, Tx: 2, Endpoint: "192.0.2.1:1"}}, nil
}

func (r *recorder) Apply(_ context.Context, rs nft.Ruleset) (bool, error) {
	r.steps = append(r.steps, "firewall")
	r.ruleset = rs
	if r.failFW {
		return false, errors.New("nft: syntax error")
	}
	return true, nil
}

func TestApplyOrderAndRevision(t *testing.T) {
	rec := &recorder{}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	a := &Agent{Iface: "wg-pf0", WG: rec, FW: rec, Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s := vpnagent.SyncResponse{Revision: 3, Active: []vpnagent.Activation{{Address: "10.255.0.10", ExpiresAt: now.Add(time.Minute)}}}
	if err := a.Apply(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rec.steps, []string{"interface", "firewall", "peers"}) {
		t.Fatalf("order %v", rec.steps)
	}
	if a.Revision() != 3 || a.LastError() != "" || rec.ruleset.Active["10.255.0.10"] != time.Minute {
		t.Fatalf("revision %d err %q", a.Revision(), a.LastError())
	}

	rec.failFW, rec.steps = true, nil
	if err := a.Apply(context.Background(), vpnagent.SyncResponse{Revision: 4}); err == nil {
		t.Fatal("expected an error")
	}
	if a.Revision() != 3 || a.LastError() == "" {
		t.Fatal("a failed apply must not advance the revision")
	}
	if !reflect.DeepEqual(rec.steps, []string{"interface", "firewall"}) {
		t.Fatalf("peers must not change when the firewall failed: %v", rec.steps)
	}
	if obs := a.Observe(context.Background()); len(obs) != 1 || obs[0].RxBytes != 1 || obs[0].LatestHandshake != 5 {
		t.Fatalf("observe %+v", obs)
	}
}
