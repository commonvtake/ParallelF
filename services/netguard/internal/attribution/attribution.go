// Package attribution decodes Cloud and VPN domain events into the facts
// NetGuard needs to attribute traffic: which networks exist (and which are
// labs), and who held an address when. Payloads are protojson, decoded
// field by field so NetGuard depends on the contract, not on generated code.
package attribution

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Subjects consumed.
const (
	CloudNetworkCreated  = "pf.cloud.evt.network.created"
	CloudNetworkDeleted  = "pf.cloud.evt.network.deleted"
	CloudWorkloadCreated = "pf.cloud.evt.workload.created"
	CloudWorkloadDeleted = "pf.cloud.evt.workload.deleted"
	VPNDeviceCreated     = "pf.vpn.evt.device.created"
	VPNDeviceState       = "pf.vpn.evt.device.state_changed"
)

// Subjects lists every subject the consumer applies.
var Subjects = []string{CloudNetworkCreated, CloudNetworkDeleted, CloudWorkloadCreated, CloudWorkloadDeleted, VPNDeviceCreated, VPNDeviceState}

// Network is a Cloud network.
type Network struct {
	ID, ProjectID, Name, Kind, CIDR string
	At                              time.Time
}

// Claim records that an entity holds an address from At on.
type Claim struct {
	IP, Kind, EntityID, Name, ProjectID, OwnerSubject string
	At                                                time.Time
}

// Release ends every open claim of an entity.
type Release struct {
	Kind, EntityID string
	At             time.Time
}

// Change is what one event means for attribution.
type Change struct {
	Network        *Network
	NetworkDeleted *Release // Kind is "network"
	Claims         []Claim
	Releases       []Release
}

type networkCreated struct {
	NetworkID string    `json:"networkId"`
	ProjectID string    `json:"projectId"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	CIDR      string    `json:"cidr"`
	CreatedAt time.Time `json:"createdAt"`
}

type networkDeleted struct {
	NetworkID string    `json:"networkId"`
	DeletedAt time.Time `json:"deletedAt"`
}

type workloadCreated struct {
	WorkloadID string    `json:"workloadId"`
	ProjectID  string    `json:"projectId"`
	Name       string    `json:"name"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `json:"createdAt"`
}

type workloadDeleted struct {
	WorkloadID string    `json:"workloadId"`
	DeletedAt  time.Time `json:"deletedAt"`
}

type deviceCreated struct {
	DeviceID     string    `json:"deviceId"`
	Name         string    `json:"name"`
	OwnerSubject string    `json:"ownerSubject"`
	OwnerName    string    `json:"ownerName"`
	Address      string    `json:"address"`
	CreatedAt    time.Time `json:"createdAt"`
}

type deviceState struct {
	DeviceID  string    `json:"deviceId"`
	State     string    `json:"state"`
	ChangedAt time.Time `json:"changedAt"`
}

// Address normalizes "10.0.0.2" or "10.0.0.2/32" to the bare address.
func Address(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), true
	}
	return "", false
}

// GatewayAddress is the host's address on a Cloud network: its first
// usable address. Lab networks have none.
func GatewayAddress(cidr, kind string) (string, bool) {
	if kind == "lab" {
		return "", false
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", false
	}
	return p.Masked().Addr().Next().String(), true
}

// Decode interprets one outbox row. ok is false for subjects NetGuard does
// not use.
func Decode(subject string, payload []byte) (c Change, ok bool, err error) {
	switch subject {
	case CloudNetworkCreated:
		var m networkCreated
		if err := json.Unmarshal(payload, &m); err != nil {
			return c, false, fmt.Errorf("%s: %w", subject, err)
		}
		c.Network = &Network{ID: m.NetworkID, ProjectID: m.ProjectID, Name: m.Name, Kind: m.Kind, CIDR: m.CIDR, At: m.CreatedAt}
		if gw, ok := GatewayAddress(m.CIDR, m.Kind); ok {
			c.Claims = append(c.Claims, Claim{IP: gw, Kind: "network_gateway", EntityID: m.NetworkID, Name: m.Name + " gateway", ProjectID: m.ProjectID, At: m.CreatedAt})
		}
	case CloudNetworkDeleted:
		var m networkDeleted
		if err := json.Unmarshal(payload, &m); err != nil {
			return c, false, fmt.Errorf("%s: %w", subject, err)
		}
		c.NetworkDeleted = &Release{Kind: "network", EntityID: m.NetworkID, At: m.DeletedAt}
		c.Releases = append(c.Releases, Release{Kind: "network_gateway", EntityID: m.NetworkID, At: m.DeletedAt})
	case CloudWorkloadCreated:
		var m workloadCreated
		if err := json.Unmarshal(payload, &m); err != nil {
			return c, false, fmt.Errorf("%s: %w", subject, err)
		}
		if ip, ok := Address(m.IP); ok {
			c.Claims = append(c.Claims, Claim{IP: ip, Kind: "workload", EntityID: m.WorkloadID, Name: m.Name, ProjectID: m.ProjectID, At: m.CreatedAt})
		}
	case CloudWorkloadDeleted:
		var m workloadDeleted
		if err := json.Unmarshal(payload, &m); err != nil {
			return c, false, fmt.Errorf("%s: %w", subject, err)
		}
		c.Releases = append(c.Releases, Release{Kind: "workload", EntityID: m.WorkloadID, At: m.DeletedAt})
	case VPNDeviceCreated:
		var m deviceCreated
		if err := json.Unmarshal(payload, &m); err != nil {
			return c, false, fmt.Errorf("%s: %w", subject, err)
		}
		if ip, ok := Address(m.Address); ok {
			name := m.Name
			if m.OwnerName != "" {
				name = m.OwnerName + "/" + m.Name
			}
			c.Claims = append(c.Claims, Claim{IP: ip, Kind: "vpn_device", EntityID: m.DeviceID, Name: name, OwnerSubject: m.OwnerSubject, At: m.CreatedAt})
		}
	case VPNDeviceState:
		var m deviceState
		if err := json.Unmarshal(payload, &m); err != nil {
			return c, false, fmt.Errorf("%s: %w", subject, err)
		}
		if m.State == "REVOKED" || m.State == "EXPIRED" {
			c.Releases = append(c.Releases, Release{Kind: "vpn_device", EntityID: m.DeviceID, At: m.ChangedAt})
		}
	default:
		return c, false, nil
	}
	return c, true, nil
}
