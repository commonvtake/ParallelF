// Package ipam plans addresses on ParallelF networks.
//
// Layout of a network, e.g. 10.20.1.0/24 of kind nat:
//
//	10.20.1.0          network address
//	10.20.1.1          gateway: the host's address on the bridge (not on lab networks)
//	10.20.1.2 - .248   assigned to workloads, lowest free first
//	10.20.1.249 - .254 DHCP spare pool for unknown MAC addresses (not on lab networks)
//	10.20.1.255        broadcast
//
// Every workload's address is chosen here and recorded in PostgreSQL;
// DHCP only hands out these reservations, so the database is the single
// source of truth for addressing.
package ipam

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Network kinds (mirrors pkg/cloudagent).
const (
	KindNAT      = "nat"
	KindIsolated = "isolated"
	KindLab      = "lab"
)

const (
	// MinPrefix and MaxPrefix bound network sizes: /16 (65 534 hosts) to
	// /27 (30 hosts).
	MinPrefix = 16
	MaxPrefix = 27
	// DHCPSpareSize addresses at the top of nat and isolated networks are
	// left to DHCP for MAC addresses the platform does not know.
	DHCPSpareSize = 6
)

var (
	// Pool contains every ParallelF network.
	Pool = netip.MustParsePrefix("10.0.0.0/8")
	// Reserved is kept for the VPN tunnel and platform services.
	Reserved = netip.MustParsePrefix("10.255.0.0/16")

	// ErrExhausted means every assignable address is in use.
	ErrExhausted = errors.New("no free address left on the network")
)

// ValidateCIDR parses and checks a network CIDR. It must be an IPv4 network
// address (no host bits) inside 10.0.0.0/8, outside 10.255.0.0/16, and
// between /16 and /27.
func ValidateCIDR(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("must be an IPv4 network in CIDR notation, e.g. 10.20.1.0/24")
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("has host bits set; the network address is %s", p.Masked())
	}
	if p.Bits() < MinPrefix || p.Bits() > MaxPrefix {
		return netip.Prefix{}, fmt.Errorf("prefix length must be between /%d and /%d", MinPrefix, MaxPrefix)
	}
	if !Pool.Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("must be inside %s", Pool)
	}
	if p.Overlaps(Reserved) {
		return netip.Prefix{}, fmt.Errorf("must not overlap %s, which is reserved for the VPN", Reserved)
	}
	return p, nil
}

// ValidKind reports whether kind is a known network kind.
func ValidKind(kind string) bool {
	return kind == KindNAT || kind == KindIsolated || kind == KindLab
}

func offset(p netip.Prefix, n uint32) netip.Addr {
	b := p.Masked().Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += n
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func size(p netip.Prefix) uint32 { return 1 << (32 - p.Bits()) }

// Gateway returns the host's address on the network, or false for lab
// networks, where the host has none.
func Gateway(p netip.Prefix, kind string) (netip.Addr, bool) {
	if kind == KindLab {
		return netip.Addr{}, false
	}
	return offset(p, 1), true
}

// DHCPSpare returns the first and last address of the DHCP spare pool, or
// false for lab networks, which have no DHCP server.
func DHCPSpare(p netip.Prefix, kind string) (first, last netip.Addr, ok bool) {
	if kind == KindLab {
		return netip.Addr{}, netip.Addr{}, false
	}
	n := size(p)
	return offset(p, n-1-DHCPSpareSize), offset(p, n-2), true
}

// AssignableRange returns the first and last address that can be given to
// a workload.
func AssignableRange(p netip.Prefix, kind string) (first, last netip.Addr) {
	n := size(p)
	end := n - 2 // broadcast - 1
	if kind != KindLab {
		end -= DHCPSpareSize
	}
	return offset(p, 2), offset(p, end)
}

// Capacity is the number of workload addresses on the network.
func Capacity(p netip.Prefix, kind string) int {
	first, last := AssignableRange(p, kind)
	a, b := first.As4(), last.As4()
	f := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	l := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return int(l-f) + 1
}

// NextFree returns the lowest assignable address not in used.
func NextFree(p netip.Prefix, kind string, used map[netip.Addr]bool) (netip.Addr, error) {
	first, last := AssignableRange(p, kind)
	for a := first; a.Compare(last) <= 0; a = a.Next() {
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}

// RandomMAC returns a locally administered unicast MAC address in the
// 52:54:00 prefix that QEMU/KVM guests conventionally use.
func RandomMAC() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("ipam: crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", b[0], b[1], b[2])
}

// BridgeName derives the Linux bridge name for a network id. Interface
// names are limited to 15 bytes, so the last 8 hex digits of the id (the
// random part of a UUIDv7) are used; the database enforces uniqueness.
func BridgeName(networkID string) string {
	hex := strings.ReplaceAll(networkID, "-", "")
	if len(hex) < 8 {
		return "pfbr-" + hex
	}
	return "pfbr-" + hex[len(hex)-8:]
}
