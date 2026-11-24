// Package ngsensor is the protocol between pf-netguardd and its sensors
// (pf-ng-sensor), and the signed discovery-scope format both enforce.
package ngsensor

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// VersionHeader carries Version on every request.
const (
	VersionHeader = "X-PF-NG-Sensor-Protocol"
	Version       = "1"
)

// Paths on pf-netguardd's sensor listener.
const (
	PathRegister = "/agent/v1/register"
	PathIngest   = "/agent/v1/ingest"
)

// Limits every sensor and pf-netguardd apply to telemetry. Values seen on
// the wire are attacker-controlled; nothing longer is stored.
const (
	MaxLineBytes   = 64 << 10
	MaxFieldBytes  = 512
	MaxBatchEvents = 2000
)

// Event kinds.
const (
	KindFlow      = "flow"
	KindDNS       = "dns"
	KindHTTP      = "http"
	KindTLS       = "tls"
	KindAlert     = "alert"
	KindAnomaly   = "anomaly"
	KindDiscovery = "discovery"
)

// RegisterRequest is sent once, with the join token.
type RegisterRequest struct {
	Name         string `json:"name"`
	AgentVersion string `json:"agent_version"`
	Engine       string `json:"engine"` // e.g. "Suricata 7.0.3"
}

// RegisterResponse carries the sensor's credential and the public key
// discovery scopes are signed with; the sensor pins it.
type RegisterResponse struct {
	SensorID       string `json:"sensor_id"`
	Credential     string `json:"credential"`
	ScopePublicKey string `json:"scope_public_key"` // base64 Ed25519
}

// Event is one normalized telemetry record.
type Event struct {
	Time        time.Time `json:"ts"`
	Kind        string    `json:"kind"`
	Interface   string    `json:"iface,omitempty"`
	SrcIP       string    `json:"src_ip,omitempty"`
	SrcPort     int       `json:"src_port,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	DstPort     int       `json:"dst_port,omitempty"`
	Proto       string    `json:"proto,omitempty"`
	CommunityID string    `json:"community_id,omitempty"`
	AppProto    string    `json:"app_proto,omitempty"`
	// Details holds the kind-specific fields (dns.rrname, alert.signature,
	// flow.bytes_toserver, ...), already truncated.
	Details map[string]string `json:"details,omitempty"`
	// RawSHA256 is the hex SHA-256 of the source line: provenance, and the
	// key that makes re-delivery idempotent.
	RawSHA256 string `json:"raw_sha256"`
}

// IngestRequest delivers a batch and works as the sensor's heartbeat.
type IngestRequest struct {
	Engine     string   `json:"engine"`
	Interfaces []string `json:"interfaces"`
	Events     []Event  `json:"events"`
	// EngineError is set while the capture engine is not running.
	EngineError string `json:"engine_error,omitempty"`
}

// IngestResponse acknowledges the batch and carries the discovery scopes
// the sensor should run.
type IngestResponse struct {
	Accepted int           `json:"accepted"`
	Scopes   []SignedScope `json:"scopes"`
}

// --- Discovery scopes -------------------------------------------------------------

// Techniques a scope may allow. There are no others: no SYN scans, no OS
// fingerprinting, nothing that sends more than a ping or a TCP connect.
const (
	TechniqueICMPEcho   = "icmp-echo"
	TechniqueTCPConnect = "tcp-connect"
)

// Scope authorises active discovery of networks the owner controls.
type Scope struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	CIDRs      []string  `json:"cidrs"`
	Techniques []string  `json:"techniques"`
	Ports      []int     `json:"ports"`
	RatePPS    int       `json:"rate_pps"`
	ValidUntil time.Time `json:"valid_until"`
	IssuedAt   time.Time `json:"issued_at"`
}

// SignedScope is a scope document and its Ed25519 signature.
type SignedScope struct {
	Document  string `json:"document"`  // base64 of the canonical JSON
	Signature string `json:"signature"` // base64
}

// Hard limits, enforced on both sides regardless of what a scope says.
const (
	MaxScopePrefixBits = 22 // no network larger than a /22
	MaxScopeRatePPS    = 100
	MaxScopePorts      = 32
	MaxScopeCIDRs      = 8
)

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
}

// CheckGuards applies the guards that no scope can lift: private IPv4
// ranges only, at most a /22 each, allowlisted techniques, bounded ports
// and rate.
func CheckGuards(s Scope) error {
	if len(s.CIDRs) == 0 || len(s.CIDRs) > MaxScopeCIDRs {
		return fmt.Errorf("a scope needs 1 to %d CIDRs", MaxScopeCIDRs)
	}
	for _, c := range s.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("%q is not an IPv4 CIDR", c)
		}
		if p.Bits() < MaxScopePrefixBits {
			return fmt.Errorf("%s is larger than a /%d", c, MaxScopePrefixBits)
		}
		inside := false
		for _, r := range privateRanges {
			if r.Contains(p.Masked().Addr()) && r.Bits() <= p.Bits() {
				inside = true
			}
		}
		if !inside {
			return fmt.Errorf("%s is not a private (RFC 1918 or CGNAT) range", c)
		}
	}
	if len(s.Techniques) == 0 {
		return errors.New("a scope needs at least one technique")
	}
	for _, t := range s.Techniques {
		if t != TechniqueICMPEcho && t != TechniqueTCPConnect {
			return fmt.Errorf("technique %q is not allowed", t)
		}
	}
	if slices.Contains(s.Techniques, TechniqueTCPConnect) && len(s.Ports) == 0 {
		return errors.New("tcp-connect needs ports")
	}
	if len(s.Ports) > MaxScopePorts {
		return fmt.Errorf("at most %d ports", MaxScopePorts)
	}
	for _, p := range s.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d", p)
		}
	}
	if s.RatePPS < 1 || s.RatePPS > MaxScopeRatePPS {
		return fmt.Errorf("rate must be 1 to %d probes per second", MaxScopeRatePPS)
	}
	return nil
}

// Sign returns the signed form of s.
func Sign(s Scope, key ed25519.PrivateKey) (SignedScope, error) {
	doc, err := json.Marshal(s)
	if err != nil {
		return SignedScope{}, err
	}
	return SignedScope{
		Document:  base64.StdEncoding.EncodeToString(doc),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, doc)),
	}, nil
}

// Verify checks the signature with the pinned key, then the expiry and
// the guards, and returns the scope.
func Verify(ss SignedScope, key ed25519.PublicKey, now time.Time) (Scope, error) {
	doc, err := base64.StdEncoding.DecodeString(ss.Document)
	if err != nil {
		return Scope{}, errors.New("scope document is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(ss.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, doc, sig) {
		return Scope{}, errors.New("scope signature does not verify")
	}
	var s Scope
	if err := json.Unmarshal(doc, &s); err != nil {
		return Scope{}, fmt.Errorf("scope document: %w", err)
	}
	if !now.Before(s.ValidUntil) {
		return Scope{}, fmt.Errorf("scope %s expired at %s", s.ID, s.ValidUntil.Format(time.RFC3339))
	}
	if err := CheckGuards(s); err != nil {
		return Scope{}, fmt.Errorf("scope %s: %w", s.ID, err)
	}
	return s, nil
}
