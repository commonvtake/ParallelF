// Package detect turns telemetry into findings. Detectors are pure: the
// store gathers what they need (lab networks, which addresses are known,
// windowed scan counts, issued scopes) and persists what they return.
//
// Detectors:
//
//	suricata.passthrough   every Suricata alert, severity from its priority
//	ng.port_scan           one source reaching many ports on one host, or one
//	                       port on many hosts, within a window
//	ng.new_device          an address nobody attributed appears as a source
//	ng.lab_egress_attempt  a lab-network workload tries to reach anything
//	                       outside its own lab network
//	ng.dns_anomaly         query names shaped like tunnelling or exfiltration
package detect

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// Detector names.
const (
	SuricataPassthrough = "suricata.passthrough"
	PortScan            = "ng.port_scan"
	NewDevice           = "ng.new_device"
	LabEgress           = "ng.lab_egress_attempt"
	DNSAnomaly          = "ng.dns_anomaly"
)

// Finding is one detection; findings with the same DedupeKey fold into one
// live alert.
type Finding struct {
	Detector  string
	RuleID    string
	Severity  string
	Title     string
	SrcIP     string
	DstIP     string
	DedupeKey string
	EventID   int64
	Time      time.Time
	Details   map[string]string
}

// ScanCount is a windowed aggregate the store computes for the sources in
// a batch. Vertical: Dst set, Distinct ports. Horizontal: Port set,
// Distinct hosts.
type ScanCount struct {
	Src         string
	Dst         string
	Port        int
	Distinct    int
	LastEventID int64
	LastSeen    time.Time
}

// Inputs is what detectors may consult beyond the batch itself.
type Inputs struct {
	LabNetworks []netip.Prefix
	// Monitored ranges where an unattributed source is a new device.
	Monitored []netip.Prefix
	// Seen holds addresses NetGuard saw before this batch.
	Seen map[string]bool
	// Attributed holds addresses that currently belong to a workload, VPN
	// device, network gateway or configured infrastructure.
	Attributed map[string]bool
	Vertical   []ScanCount
	Horizontal []ScanCount
	// Scopes are discovery scopes valid (or recently valid) in this window.
	Scopes []ngsensor.Scope
}

// Thresholds.
const (
	ScanWindow       = 60 * time.Second
	ScanThreshold    = 20
	maxNameLength    = 120
	maxLabelLength   = 50
	entropyMinLength = 24
	entropyThreshold = 3.8
)

// Run applies every detector to a batch.
func Run(batch []domain.Event, in Inputs) []Finding {
	var out []Finding
	newSeen := map[string]bool{}
	for _, e := range batch {
		switch e.Kind {
		case ngsensor.KindAlert:
			out = append(out, suricata(e))
		case ngsensor.KindDNS:
			if f, ok := dnsAnomaly(e); ok {
				out = append(out, f)
			}
		}
		if e.Kind == ngsensor.KindFlow || e.Kind == ngsensor.KindDNS || e.Kind == ngsensor.KindHTTP || e.Kind == ngsensor.KindTLS {
			if f, ok := labEgress(e, in.LabNetworks); ok {
				out = append(out, f)
			}
		}
		if e.Kind == ngsensor.KindFlow && e.SrcIP != "" && !newSeen[e.SrcIP] && !in.Seen[e.SrcIP] && !in.Attributed[e.SrcIP] && within(e.SrcIP, in.Monitored) {
			newSeen[e.SrcIP] = true
			out = append(out, Finding{
				Detector: NewDevice, RuleID: NewDevice, Severity: "medium",
				Title: fmt.Sprintf("Unattributed device %s appeared on %s", e.SrcIP, orUnknown(e.Interface)),
				SrcIP: e.SrcIP, DedupeKey: "new_device:" + e.SrcIP, EventID: e.ID, Time: e.Time,
				Details: map[string]string{"iface": e.Interface},
			})
		}
	}
	out = append(out, scans(in)...)
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown interface"
	}
	return s
}

func within(ip string, nets []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func suricata(e domain.Event) Finding {
	sid := e.Details["alert.signature_id"]
	sev := "info"
	switch e.Details["alert.severity"] {
	case "1":
		sev = "high"
	case "2":
		sev = "medium"
	case "3":
		sev = "low"
	}
	title := e.Details["alert.signature"]
	if title == "" {
		title = "Suricata signature " + sid
	}
	return Finding{
		Detector: SuricataPassthrough, RuleID: "sid:" + sid, Severity: sev, Title: title,
		SrcIP: e.SrcIP, DstIP: e.DstIP, DedupeKey: "suricata:" + sid + ":" + e.SrcIP + ">" + e.DstIP,
		EventID: e.ID, Time: e.Time,
		Details: map[string]string{"signature_id": sid, "category": e.Details["alert.category"], "action": e.Details["alert.action"], "community_id": e.CommunityID},
	}
}

func labEgress(e domain.Event, labs []netip.Prefix) (Finding, bool) {
	src, err1 := netip.ParseAddr(e.SrcIP)
	dst, err2 := netip.ParseAddr(e.DstIP)
	if err1 != nil || err2 != nil || dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return Finding{}, false
	}
	for _, lab := range labs {
		if !lab.Contains(src) || lab.Contains(dst) {
			continue
		}
		// The lab network's own broadcast address stays inside it.
		return Finding{
			Detector: LabEgress, RuleID: LabEgress, Severity: "high",
			Title: fmt.Sprintf("Lab workload %s tried to reach %s outside its lab network", e.SrcIP, e.DstIP),
			SrcIP: e.SrcIP, DstIP: e.DstIP, DedupeKey: "lab_egress:" + e.SrcIP + ">" + e.DstIP,
			EventID: e.ID, Time: e.Time,
			Details: map[string]string{"lab_network": lab.String(), "dst_port": strconv.Itoa(e.DstPort), "proto": e.Proto, "app_proto": e.AppProto},
		}, true
	}
	return Finding{}, false
}

// Entropy is the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	h := 0.0
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// RegisteredDomain approximates the registrable part of a name (its last
// two labels), which is what tunnelling keeps constant.
func RegisteredDomain(name string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) <= 2 {
		return strings.Join(labels, ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func dnsAnomaly(e domain.Event) (Finding, bool) {
	if t := e.Details["dns.type"]; t != "" && t != "query" && t != "request" {
		return Finding{}, false
	}
	name := strings.ToLower(strings.TrimSuffix(e.Details["dns.rrname"], "."))
	if name == "" {
		return Finding{}, false
	}
	var reasons []string
	if len(name) > maxNameLength {
		reasons = append(reasons, fmt.Sprintf("name is %d characters long", len(name)))
	}
	labels := strings.Split(name, ".")
	for _, l := range labels[:max(len(labels)-2, 0)] {
		if len(l) > maxLabelLength {
			reasons = append(reasons, fmt.Sprintf("a label is %d characters long", len(l)))
			break
		}
		if len(l) >= entropyMinLength {
			if h := Entropy(l); h >= entropyThreshold {
				reasons = append(reasons, fmt.Sprintf("a label looks random (%.1f bits per character)", h))
				break
			}
		}
	}
	if len(reasons) == 0 {
		return Finding{}, false
	}
	base := RegisteredDomain(name)
	return Finding{
		Detector: DNSAnomaly, RuleID: DNSAnomaly, Severity: "medium",
		Title: fmt.Sprintf("DNS queries for %s look like tunnelling or exfiltration", base),
		SrcIP: e.SrcIP, DstIP: e.DstIP, DedupeKey: "dns_anomaly:" + e.SrcIP + ":" + base,
		EventID: e.ID, Time: e.Time,
		Details: map[string]string{"query": name, "domain": base, "reasons": strings.Join(reasons, "; ")},
	}, true
}

// scopeFor returns the issued scope covering dst at t, if any.
func scopeFor(dst string, t time.Time, scopes []ngsensor.Scope) (ngsensor.Scope, bool) {
	a, err := netip.ParseAddr(dst)
	if err != nil {
		return ngsensor.Scope{}, false
	}
	for _, s := range scopes {
		if t.Before(s.IssuedAt.Add(-time.Minute)) || t.After(s.ValidUntil.Add(5*time.Minute)) {
			continue
		}
		for _, c := range s.CIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
				return s, true
			}
		}
	}
	return ngsensor.Scope{}, false
}

func scans(in Inputs) []Finding {
	var out []Finding
	add := func(c ScanCount, vertical bool) {
		var title, key, target string
		details := map[string]string{"distinct": strconv.Itoa(c.Distinct), "window": ScanWindow.String()}
		if vertical {
			target = c.Dst
			title = fmt.Sprintf("Port scan: %s reached %d ports on %s within %s", c.Src, c.Distinct, c.Dst, ScanWindow)
			key = "port_scan:v:" + c.Src + ">" + c.Dst
			details["pattern"] = "vertical"
		} else {
			title = fmt.Sprintf("Port sweep: %s reached port %d on %d hosts within %s", c.Src, c.Port, c.Distinct, ScanWindow)
			key = "port_scan:h:" + c.Src + ":" + strconv.Itoa(c.Port)
			details["pattern"] = "horizontal"
			details["port"] = strconv.Itoa(c.Port)
		}
		sev := "high"
		if target != "" {
			if s, ok := scopeFor(target, c.LastSeen, in.Scopes); ok {
				// Authorised discovery is still recorded, at the lowest severity.
				sev = "info"
				title += " (matches authorised discovery scope " + s.Name + ")"
				details["scope_id"] = s.ID
			}
		}
		out = append(out, Finding{
			Detector: PortScan, RuleID: PortScan + ":" + details["pattern"], Severity: sev, Title: title,
			SrcIP: c.Src, DstIP: target, DedupeKey: key, EventID: c.LastEventID, Time: c.LastSeen, Details: details,
		})
	}
	for _, c := range in.Vertical {
		if c.Distinct >= ScanThreshold {
			add(c, true)
		}
	}
	for _, c := range in.Horizontal {
		if c.Distinct >= ScanThreshold {
			add(c, false)
		}
	}
	slices.SortFunc(out, func(a, b Finding) int { return strings.Compare(a.DedupeKey, b.DedupeKey) })
	return out
}
