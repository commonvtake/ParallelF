// Package agent converges the gateway to the desired state from pf-vpnd:
// the WireGuard interface and its peers, and the nftables table that
// enforces activations and policies.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/nft"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/wg"
)

// WG is the part of the WireGuard manager the agent uses.
type WG interface {
	EnsureInterface(ctx context.Context, want vpnagent.Interface) error
	SyncPeers(ctx context.Context, want []vpnagent.Peer) (int, error)
	Peers(ctx context.Context) ([]wg.Peer, error)
}

// Firewall is the part of the nftables applier the agent uses.
type Firewall interface {
	Apply(ctx context.Context, r nft.Ruleset) (bool, error)
}

// Agent applies desired state.
type Agent struct {
	Iface  string
	WG     WG
	FW     Firewall
	Now    func() time.Time
	Logger *slog.Logger

	revision int64
	lastErr  string
}

// Revision is the desired-state revision last applied without error.
func (a *Agent) Revision() int64 { return a.revision }

// LastError is the last apply error, or empty.
func (a *Agent) LastError() string { return a.lastErr }

// Apply converges to s. The order matters: the firewall table first, so a
// new peer is filtered before it can send anything, then the peers, where
// removals come first and flush the removed addresses' connections.
func (a *Agent) Apply(ctx context.Context, s vpnagent.SyncResponse) error {
	err := a.apply(ctx, s)
	if err != nil {
		a.lastErr = err.Error()
		return err
	}
	a.lastErr = ""
	a.revision = s.Revision
	return nil
}

func (a *Agent) apply(ctx context.Context, s vpnagent.SyncResponse) error {
	if err := a.WG.EnsureInterface(ctx, s.Interface); err != nil {
		return fmt.Errorf("interface: %w", err)
	}
	rules, err := nft.Render(a.Iface, s, a.Now())
	if err != nil {
		return fmt.Errorf("render firewall: %w", err)
	}
	replaced, err := a.FW.Apply(ctx, rules)
	if err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	changes, err := a.WG.SyncPeers(ctx, s.Peers)
	if err != nil {
		return fmt.Errorf("peers: %w", err)
	}
	if replaced || changes > 0 || s.Revision != a.revision {
		a.Logger.Info("applied desired state", slog.Int64("revision", s.Revision),
			slog.Int("peers", len(s.Peers)), slog.Int("active", len(rules.Active)),
			slog.Int("policies", len(s.Policies)), slog.Int("peer_changes", changes), slog.Bool("table_replaced", replaced))
	}
	return nil
}

// Observe reports the configured peers.
func (a *Agent) Observe(ctx context.Context) []vpnagent.PeerStatus {
	peers, err := a.WG.Peers(ctx)
	if err != nil {
		a.Logger.Warn("read peers", slog.String("error", err.Error()))
		return nil
	}
	out := make([]vpnagent.PeerStatus, 0, len(peers))
	for _, p := range peers {
		out = append(out, vpnagent.PeerStatus{PublicKey: p.PublicKey, LatestHandshake: p.Handshake, RxBytes: p.Rx, TxBytes: p.Tx, Endpoint: p.Endpoint})
	}
	return out
}
