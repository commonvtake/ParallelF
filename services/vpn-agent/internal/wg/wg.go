// Package wg manages the gateway's kernel WireGuard interface with the
// standard wg(8) and ip(8) tools.
package wg

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/hostexec"
)

// Manager owns one WireGuard interface.
type Manager struct {
	Iface   string
	KeyPath string
	Run     hostexec.Runner
	// RemoveHook runs after a peer is removed, with its tunnel addresses
	// (to flush their connection-tracking state).
	RemoveHook func(ctx context.Context, addresses []string)
}

// ValidKey reports whether s is a base64 WireGuard key (32 bytes).
func ValidKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// EnsureKey creates the gateway's private key on first use (mode 0600)
// and returns the public key. The private key never leaves this host.
func (m *Manager) EnsureKey(ctx context.Context) (string, error) {
	private, err := os.ReadFile(m.KeyPath)
	if errors.Is(err, os.ErrNotExist) {
		private, err = m.Run.Run(ctx, nil, "wg", "genkey")
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(m.KeyPath), 0o700); err != nil {
			return "", err
		}
		tmp := m.KeyPath + ".tmp"
		if err := os.WriteFile(tmp, private, 0o600); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, m.KeyPath); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	public, err := m.Run.Run(ctx, bytes.TrimSpace(private), "wg", "pubkey")
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(public))
	if !ValidKey(key) {
		return "", fmt.Errorf("wg pubkey returned %q", key)
	}
	return key, nil
}

// EnsureInterface creates and configures the interface. Every step is
// idempotent.
func (m *Manager) EnsureInterface(ctx context.Context, want vpnagent.Interface) error {
	if _, err := m.Run.Run(ctx, nil, "ip", "link", "show", "dev", m.Iface); err != nil {
		if _, err := m.Run.Run(ctx, nil, "ip", "link", "add", "dev", m.Iface, "type", "wireguard"); err != nil {
			return err
		}
	}
	// The key goes to wg on stdin, like pre-shared keys: Ubuntu's AppArmor
	// profile for wg does not let it open files elsewhere, and no other
	// process needs to open the key file.
	private, err := os.ReadFile(m.KeyPath)
	if err != nil {
		return fmt.Errorf("read the gateway key: %w", err)
	}
	if _, err := m.Run.Run(ctx, bytes.TrimSpace(private), "wg", "set", m.Iface,
		"listen-port", strconv.Itoa(want.ListenPort), "private-key", "/dev/stdin"); err != nil {
		return err
	}
	if _, err := m.Run.Run(ctx, nil, "ip", "-4", "address", "replace", want.Address, "dev", m.Iface); err != nil {
		return err
	}
	if _, err := m.Run.Run(ctx, nil, "ip", "link", "set", "dev", m.Iface, "up"); err != nil {
		return err
	}
	if want.Forwarding {
		// Only ever switched on; the host may forward for other reasons.
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
			return fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
	}
	return nil
}

// Peer is a configured peer as `wg show dump` reports it.
type Peer struct {
	PublicKey    string
	PresharedKey string // empty for none
	Endpoint     string
	AllowedIPs   []string
	Handshake    int64
	Rx, Tx       int64
}

// ParseDump parses `wg show <iface> dump`: the interface line, then one
// tab-separated line per peer.
func ParseDump(out []byte) ([]Peer, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var peers []Peer
	for i, line := range lines {
		if i == 0 || line == "" {
			continue // the interface's own line
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return nil, fmt.Errorf("wg dump line %d has %d fields", i+1, len(f))
		}
		p := Peer{PublicKey: f[0]}
		if f[1] != "(none)" {
			p.PresharedKey = f[1]
		}
		if f[2] != "(none)" {
			p.Endpoint = f[2]
		}
		if f[3] != "(none)" && f[3] != "" {
			p.AllowedIPs = strings.Split(f[3], ",")
		}
		var err error
		if p.Handshake, err = strconv.ParseInt(f[4], 10, 64); err != nil {
			return nil, fmt.Errorf("wg dump handshake %q: %w", f[4], err)
		}
		if p.Rx, err = strconv.ParseInt(f[5], 10, 64); err != nil {
			return nil, fmt.Errorf("wg dump rx %q: %w", f[5], err)
		}
		if p.Tx, err = strconv.ParseInt(f[6], 10, 64); err != nil {
			return nil, fmt.Errorf("wg dump tx %q: %w", f[6], err)
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// Peers returns the interface's peers, or none if it does not exist yet.
func (m *Manager) Peers(ctx context.Context) ([]Peer, error) {
	out, err := m.Run.Run(ctx, nil, "wg", "show", m.Iface, "dump")
	if err != nil {
		if _, linkErr := m.Run.Run(ctx, nil, "ip", "link", "show", "dev", m.Iface); linkErr != nil {
			return nil, nil
		}
		return nil, err
	}
	return ParseDump(out)
}

// SyncPeers makes the interface's peers exactly want: adds and updates
// peers, and removes any other peer. It returns the number of changes.
func (m *Manager) SyncPeers(ctx context.Context, want []vpnagent.Peer) (int, error) {
	have, err := m.Peers(ctx)
	if err != nil {
		return 0, err
	}
	current := map[string]Peer{}
	for _, p := range have {
		current[p.PublicKey] = p
	}
	desired := map[string]vpnagent.Peer{}
	for _, p := range want {
		if !ValidKey(p.PublicKey) {
			return 0, fmt.Errorf("device %s has an invalid public key", p.DeviceID)
		}
		desired[p.PublicKey] = p
	}

	changes := 0
	var errs []error
	// Removals first: a revoked key must stop working as early as possible.
	var removed []string
	for key, p := range current {
		if _, ok := desired[key]; ok {
			continue
		}
		if _, err := m.Run.Run(ctx, nil, "wg", "set", m.Iface, "peer", key, "remove"); err != nil {
			errs = append(errs, err)
			continue
		}
		changes++
		removed = append(removed, stripPrefixes(p.AllowedIPs)...)
	}
	if len(removed) > 0 && m.RemoveHook != nil {
		sort.Strings(removed)
		m.RemoveHook(ctx, removed)
	}

	keys := make([]string, 0, len(desired))
	for k := range desired {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := desired[key]
		allowed := p.Address + "/32"
		if cur, ok := current[key]; ok && len(cur.AllowedIPs) == 1 && cur.AllowedIPs[0] == allowed && cur.PresharedKey == p.PresharedKey {
			continue
		}
		// The pre-shared key travels on stdin, never in an argument
		// (arguments are visible to every user on the host).
		psk := []byte(p.PresharedKey)
		pskSource := "/dev/stdin"
		if p.PresharedKey == "" {
			psk, pskSource = nil, "/dev/null" // an empty key file removes the key
		}
		if _, err := m.Run.Run(ctx, psk, "wg", "set", m.Iface, "peer", key,
			"allowed-ips", allowed, "preshared-key", pskSource); err != nil {
			errs = append(errs, err)
			continue
		}
		changes++
	}
	return changes, errors.Join(errs...)
}

func stripPrefixes(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		ip, _, _ := strings.Cut(c, "/")
		out = append(out, ip)
	}
	return out
}
