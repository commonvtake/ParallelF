// Package vpnagent is the protocol between pf-vpnd and the WireGuard
// gateway agent (pf-wg-agent).
//
// Like the cloud agent protocol it is level-triggered: the agent posts what
// it observes and receives the complete desired state of its gateway. A
// sync may wait (long-poll) until the desired state changes, so a
// revocation reaches the gateway within a second instead of a polling
// interval.
package vpnagent

import "time"

// VersionHeader carries Version on every request.
const (
	VersionHeader = "X-PF-VPN-Agent-Protocol"
	Version       = "1"
)

// Paths on pf-vpnd's agent listener.
const (
	PathRegister = "/agent/v1/register"
	PathSync     = "/agent/v1/sync"
)

// MaxWait bounds how long pf-vpnd holds a sync open.
const MaxWait = 25 * time.Second

// RegisterRequest is sent once, with the shared join token.
type RegisterRequest struct {
	Name         string `json:"name"`
	AgentVersion string `json:"agent_version"`
	// PublicKey is the gateway's WireGuard public key (base64). The private
	// key never leaves the gateway host.
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint"` // host:port clients dial
	ListenPort int    `json:"listen_port"`
}

// RegisterResponse carries the gateway's credential, shown once.
type RegisterResponse struct {
	GatewayID  string `json:"gateway_id"`
	Credential string `json:"credential"`
}

// SyncRequest reports what the gateway observes.
type SyncRequest struct {
	// Revision is the desired-state revision the agent last applied.
	Revision int64 `json:"revision"`
	// WaitSeconds asks pf-vpnd to hold the request until the revision
	// differs from Revision, at most this long (capped at MaxWait).
	WaitSeconds int          `json:"wait_seconds"`
	PublicKey   string       `json:"public_key"`
	Endpoint    string       `json:"endpoint"`
	Peers       []PeerStatus `json:"peers"`
	// ApplyError is the last error applying desired state, or empty.
	ApplyError string `json:"apply_error,omitempty"`
}

// PeerStatus is one configured peer as the kernel reports it.
type PeerStatus struct {
	PublicKey string `json:"public_key"`
	// LatestHandshake is a Unix time; zero when no handshake happened.
	LatestHandshake int64  `json:"latest_handshake"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	Endpoint        string `json:"endpoint,omitempty"`
}

// SyncResponse is the complete desired state of the gateway.
type SyncResponse struct {
	GatewayID string    `json:"gateway_id"`
	Revision  int64     `json:"revision"`
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers"`
	// Active lists the tunnel addresses allowed to send traffic, each until
	// its expiry. The agent installs them with a kernel timeout, so access
	// ends at the expiry even if pf-vpnd is unreachable.
	Active   []Activation `json:"active"`
	Policies []Policy     `json:"policies"`
}

// Interface is the gateway's WireGuard interface.
type Interface struct {
	Address    string `json:"address"` // e.g. 10.255.0.1/22
	ListenPort int    `json:"listen_port"`
	// Forwarding asks for IPv4 forwarding (needed when a policy allows a
	// destination beyond the gateway itself).
	Forwarding bool `json:"forwarding"`
}

// Peer is one enrolled device.
type Peer struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"` // tunnel IPv4 address (no prefix)
	// PresharedKey is base64, or empty for none.
	PresharedKey string `json:"preshared_key,omitempty"`
}

// Activation lets Address send traffic until ExpiresAt.
type Activation struct {
	Address   string    `json:"address"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Policy is one compiled access rule, in evaluation order.
type Policy struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Action   string `json:"action"` // allow or deny
	// Sources are tunnel addresses (the devices in the policy's groups).
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"` // IPv4 CIDRs
	Protocol     string   `json:"protocol"`     // tcp, udp, icmp or any
	Ports        []string `json:"ports,omitempty"`
}

// Policy actions and protocols.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"

	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"
	ProtocolAny  = "any"
)
