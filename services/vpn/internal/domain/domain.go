// Package domain holds pf-vpnd's resource model and the rules that do not
// need the database: validation, tunnel addressing, connection status and
// policy compilation.
package domain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
)

// Errors the API maps to problems.
var (
	ErrNotFound        = errors.New("not found")
	ErrNameTaken       = errors.New("name already used")
	ErrKeyTaken        = errors.New("public key already enrolled")
	ErrInvalidState    = errors.New("invalid state for this operation")
	ErrNoGateway       = errors.New("no VPN gateway is registered")
	ErrPoolExhausted   = errors.New("tunnel address pool exhausted")
	ErrUnauthorizedGW  = errors.New("unknown gateway credential")
	ErrGatewayActive   = errors.New("gateway still reporting")
	ErrPSKUnavailable  = errors.New("pre-shared keys are not configured")
	ErrNotOwner        = errors.New("device belongs to another user")
	ErrReauthenticate  = errors.New("a recent sign-in is required")
	ErrMFARequired     = errors.New("multi-factor authentication is required")
	ErrPolicyReference = errors.New("invalid policy")
)

// Device lifecycle states. Whether a device is active (allowed to send
// traffic) is not a state: it is ActiveUntil in the future.
const (
	StatePending  = "PENDING"  // created; the gateway has not confirmed the peer
	StateEnrolled = "ENROLLED" // the gateway has the peer
	StateRevoked  = "REVOKED"
	StateExpired  = "EXPIRED"
)

// Gateway statuses.
const (
	GatewayReady    = "READY"
	GatewayNotReady = "NOT_READY"
)

// Connection statuses, derived from the last handshake.
const (
	ConnOnline  = "online"
	ConnIdle    = "idle"
	ConnOffline = "offline"
)

// Thresholds for connection status (clients use PersistentKeepalive=25).
const (
	OnlineWithin = 180 * time.Second
	IdleWithin   = 15 * time.Minute
)

// PlatformDestination is the policy keyword for the gateway's own tunnel
// address, where the dashboard and API are reachable over the VPN.
const PlatformDestination = "platform"

// Gateway is a WireGuard gateway host.
type Gateway struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	PublicKey       string    `json:"public_key"`
	Endpoint        string    `json:"endpoint"`
	ListenPort      int       `json:"listen_port"`
	Address         string    `json:"address"` // tunnel address with prefix, e.g. 10.255.0.1/22
	AgentVersion    string    `json:"agent_version"`
	AppliedRevision int64     `json:"applied_revision"`
	Revision        int64     `json:"revision"`
	ApplyError      string    `json:"apply_error,omitempty"`
	RegisteredAt    time.Time `json:"registered_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

// Device is an enrolled WireGuard peer, owned by one user.
type Device struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	OwnerSubject    string     `json:"owner_subject"`
	OwnerName       string     `json:"owner_name"`
	PublicKey       string     `json:"public_key"`
	Address         string     `json:"address"`
	Groups          []string   `json:"groups"`
	PresharedKey    bool       `json:"preshared_key"`
	State           string     `json:"state"`
	Active          bool       `json:"active"`
	ActiveUntil     *time.Time `json:"active_until,omitempty"`
	Connection      string     `json:"connection"`
	LastHandshakeAt *time.Time `json:"last_handshake_at,omitempty"`
	Endpoint        string     `json:"endpoint,omitempty"`
	RxBytes         int64      `json:"rx_bytes"`
	TxBytes         int64      `json:"tx_bytes"`
	ExpiresAt       time.Time  `json:"expires_at"`
	CreatedAt       time.Time  `json:"created_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`

	pskCiphertext []byte
	connected     bool
}

// PSKCiphertext is the stored, encrypted pre-shared key (nil for none).
func (d Device) PSKCiphertext() []byte { return d.pskCiphertext }

// WithPSKCiphertext returns d carrying the stored key.
func (d Device) WithPSKCiphertext(c []byte) Device {
	d.pskCiphertext = c
	d.PresharedKey = len(c) > 0
	return d
}

// Connected is the stored connection flag (used to detect changes).
func (d Device) Connected() bool { return d.connected }

// WithConnected returns d with the stored connection flag.
func (d Device) WithConnected(c bool) Device { d.connected = c; return d }

// Live reports whether the device still holds its key and address.
func (d Device) Live() bool { return d.State == StatePending || d.State == StateEnrolled }

// Derive fills the fields computed from time: Active and Connection.
func (d Device) Derive(now time.Time) Device {
	d.Active = d.Live() && d.ActiveUntil != nil && d.ActiveUntil.After(now)
	d.Connection = Connection(d.LastHandshakeAt, now)
	if !d.Live() {
		d.Connection = ConnOffline
	}
	return d
}

// Connection derives online/idle/offline from the last handshake.
func Connection(last *time.Time, now time.Time) string {
	switch {
	case last == nil || last.IsZero():
		return ConnOffline
	case now.Sub(*last) <= OnlineWithin:
		return ConnOnline
	case now.Sub(*last) <= IdleWithin:
		return ConnIdle
	}
	return ConnOffline
}

// Policy is an access rule: devices in Groups may (or may not) reach
// Destinations over Protocol/Ports. Lower priorities are evaluated first;
// anything no policy allows is denied.
type Policy struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Priority     int       `json:"priority"`
	Action       string    `json:"action"`
	Groups       []string  `json:"groups"`
	Destinations []string  `json:"destinations"`
	Protocol     string    `json:"protocol"`
	Ports        []string  `json:"ports"`
	Description  string    `json:"description"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// GatewayRegistration is a validated agent registration with the hash of
// the credential issued to it.
type GatewayRegistration struct {
	vpnagent.RegisterRequest
	TokenHash []byte
}

// Owner is the user a device is enrolled for, with the groups it starts in.
type Owner struct {
	Subject, Name string
	Groups        []string
}

// Actor identifies who performed an operation.
type Actor struct {
	Type      string
	ID        string
	Name      string
	RequestID string
}

// MetricPoint is one traffic sample: bytes since the previous sample.
type MetricPoint struct {
	At      time.Time `json:"at"`
	RxBytes int64     `json:"rx_bytes"`
	TxBytes int64     `json:"tx_bytes"`
}

// --- Validation ----------------------------------------------------------------

var (
	// NamePattern is the rule for device and policy names.
	NamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
	groupPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	portPattern  = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)
)

// FieldError describes one invalid input field.
type FieldError struct {
	Field, Code, Message string
}

// ValidationError carries the field errors of a request.
type ValidationError struct{ Errors []FieldError }

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "invalid request"
	}
	return e.Errors[0].Field + ": " + e.Errors[0].Message
}

func (e *ValidationError) add(field, code, msg string) {
	e.Errors = append(e.Errors, FieldError{field, code, msg})
}

func (e *ValidationError) orNil() error {
	if len(e.Errors) == 0 {
		return nil
	}
	return e
}

// ValidKey reports whether s is a base64 X25519 public key.
func ValidKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != s {
		return false
	}
	// An all-zero key is not a usable public key.
	for _, b := range raw {
		if b != 0 {
			return true
		}
	}
	return false
}

// DeviceInput is an enrolment request.
type DeviceInput struct {
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	PresharedKey bool   `json:"preshared_key"`
}

// Validate checks the request.
func (in DeviceInput) Validate() error {
	v := &ValidationError{}
	if !NamePattern.MatchString(in.Name) {
		v.add("name", "format", "3-40 characters: lower-case letters, digits and hyphens; starts with a letter.")
	}
	if !ValidKey(in.PublicKey) {
		v.add("public_key", "format", "Must be a base64 WireGuard public key (32 bytes). Only the public key is sent; the private key stays on the device.")
	}
	return v.orNil()
}

// ValidGroups checks a group list and returns it sorted and de-duplicated.
func ValidGroups(groups []string) ([]string, error) {
	v := &ValidationError{}
	if len(groups) > 16 {
		v.add("groups", "too_many", "At most 16 groups.")
	}
	for _, g := range groups {
		if !groupPattern.MatchString(g) {
			v.add("groups", "format", fmt.Sprintf("Group %q: lower-case letters, digits, hyphens and underscores.", g))
		}
	}
	if err := v.orNil(); err != nil {
		return nil, err
	}
	out := slices.Clone(groups)
	sort.Strings(out)
	return slices.Compact(out), nil
}

// PolicyInput creates a policy.
type PolicyInput struct {
	Name         string   `json:"name"`
	Priority     int      `json:"priority"`
	Action       string   `json:"action"`
	Groups       []string `json:"groups"`
	Destinations []string `json:"destinations"`
	Protocol     string   `json:"protocol"`
	Ports        []string `json:"ports"`
	Description  string   `json:"description"`
}

// Validate checks a policy against the tunnel network: destinations are
// "platform" or IPv4 CIDRs outside the tunnel range.
func (in *PolicyInput) Validate(tunnel netip.Prefix) error {
	v := &ValidationError{}
	if !NamePattern.MatchString(in.Name) {
		v.add("name", "format", "3-40 characters: lower-case letters, digits and hyphens; starts with a letter.")
	}
	if in.Priority < 1 || in.Priority > 10000 {
		v.add("priority", "range", "1 to 10000; lower runs first.")
	}
	if in.Action != vpnagent.ActionAllow && in.Action != vpnagent.ActionDeny {
		v.add("action", "enum", "allow or deny.")
	}
	groups, err := ValidGroups(in.Groups)
	if err != nil {
		v.Errors = append(v.Errors, err.(*ValidationError).Errors...)
	} else if len(groups) == 0 {
		v.add("groups", "required", "At least one group.")
	}
	in.Groups = groups
	if len(in.Destinations) == 0 || len(in.Destinations) > 32 {
		v.add("destinations", "count", "1 to 32 destinations.")
	}
	dests := make([]string, 0, len(in.Destinations))
	for _, d := range in.Destinations {
		if d == PlatformDestination {
			dests = append(dests, d)
			continue
		}
		p, err := netip.ParsePrefix(d)
		if err != nil || !p.Addr().Is4() {
			v.add("destinations", "format", fmt.Sprintf("%q is not \"platform\" or an IPv4 CIDR.", d))
			continue
		}
		p = p.Masked()
		if p.Overlaps(tunnel) {
			v.add("destinations", "tunnel", fmt.Sprintf("%s overlaps the tunnel network; use \"platform\" for the gateway.", p))
			continue
		}
		dests = append(dests, p.String())
	}
	sort.Strings(dests)
	in.Destinations = slices.Compact(dests)
	switch in.Protocol {
	case vpnagent.ProtocolTCP, vpnagent.ProtocolUDP:
		for _, p := range in.Ports {
			if !validPort(p) {
				v.add("ports", "format", fmt.Sprintf("%q is not a port (1-65535) or range (8000-8100).", p))
			}
		}
	case vpnagent.ProtocolICMP, vpnagent.ProtocolAny:
		if len(in.Ports) > 0 {
			v.add("ports", "not_allowed", in.Protocol+" takes no ports.")
		}
	default:
		v.add("protocol", "enum", "tcp, udp, icmp or any.")
	}
	if len(in.Ports) > 32 {
		v.add("ports", "count", "At most 32 ports or ranges.")
	}
	if in.Ports == nil {
		in.Ports = []string{}
	}
	if len(in.Description) > 500 {
		v.add("description", "length", "At most 500 characters.")
	}
	return v.orNil()
}

func validPort(p string) bool {
	m := portPattern.FindStringSubmatch(p)
	if m == nil {
		return false
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	return lo >= 1 && hi <= 65535 && lo <= hi
}

// --- Tunnel addressing ------------------------------------------------------------

// FirstDeviceOffset is the first host offset handed to devices; lower
// offsets are kept for gateways and services.
const FirstDeviceOffset = 10

// GatewayAddress is the gateway's tunnel address: the first host.
func GatewayAddress(tunnel netip.Prefix) netip.Addr { return tunnel.Masked().Addr().Next() }

// NextAddress returns the lowest free device address in tunnel.
func NextAddress(tunnel netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	a := tunnel.Masked().Addr()
	for range FirstDeviceOffset {
		a = a.Next()
	}
	for ; tunnel.Contains(a); a = a.Next() {
		if !tunnel.Contains(a.Next()) {
			break // the broadcast address
		}
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}

// --- Desired state --------------------------------------------------------------

// ClientAllowedIPs is what a device routes into the tunnel: the tunnel
// network plus the CIDRs of every allow policy that covers its groups.
func ClientAllowedIPs(tunnel netip.Prefix, groups []string, policies []Policy) []string {
	out := []string{tunnel.Masked().String()}
	for _, p := range policies {
		if p.Action != vpnagent.ActionAllow || !intersects(p.Groups, groups) {
			continue
		}
		for _, d := range p.Destinations {
			if d != PlatformDestination {
				out = append(out, d)
			}
		}
	}
	sort.Strings(out[1:])
	return append(out[:1], slices.Compact(out[1:])...)
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// CompilePolicies resolves policy groups to the tunnel addresses of live
// devices and the platform keyword to the gateway's address. It also
// reports whether any destination lies beyond the gateway (forwarding).
func CompilePolicies(policies []Policy, devices []Device, gateway netip.Addr) ([]vpnagent.Policy, bool) {
	out := make([]vpnagent.Policy, 0, len(policies))
	forwarding := false
	for _, p := range policies {
		var sources []string
		for _, d := range devices {
			if d.Live() && intersects(p.Groups, d.Groups) {
				sources = append(sources, d.Address)
			}
		}
		dests := make([]string, 0, len(p.Destinations))
		for _, d := range p.Destinations {
			if d == PlatformDestination {
				dests = append(dests, netip.PrefixFrom(gateway, 32).String())
			} else {
				dests = append(dests, d)
				if p.Action == vpnagent.ActionAllow {
					forwarding = true
				}
			}
		}
		sort.Strings(sources)
		out = append(out, vpnagent.Policy{
			Name: p.Name, Priority: p.Priority, Action: p.Action, Sources: sources,
			Destinations: dests, Protocol: p.Protocol, Ports: slices.Clone(p.Ports),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, forwarding
}

// ClientConfig is what a device needs besides its own private key.
type ClientConfig struct {
	Address             string   `json:"address"`
	GatewayPublicKey    string   `json:"gateway_public_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	// PresharedKey is returned once, when the device is created.
	PresharedKey string `json:"preshared_key,omitempty"`
}
