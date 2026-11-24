package detect

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

var t0 = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

func flow(id int64, src, dst string, port int) domain.Event {
	return domain.Event{ID: id, Time: t0, Kind: "flow", Interface: "pfbr-0a1b2c3d", SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Details: map[string]string{}}
}

func byDetector(fs []Finding) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range fs {
		out[f.Detector] = append(out[f.Detector], f)
	}
	return out
}

func TestSuricataPassthrough(t *testing.T) {
	e := domain.Event{ID: 7, Time: t0, Kind: "alert", SrcIP: "10.255.0.2", DstIP: "10.255.0.1",
		Details: map[string]string{"alert.signature_id": "9100001", "alert.signature": "PARALLELF canary: IDS self-test URI", "alert.severity": "3"}}
	f := byDetector(Run([]domain.Event{e}, Inputs{}))[SuricataPassthrough]
	if len(f) != 1 || f[0].Severity != "low" || f[0].RuleID != "sid:9100001" || f[0].EventID != 7 {
		t.Fatalf("%+v", f)
	}
}

func TestNewDevice(t *testing.T) {
	in := Inputs{
		Monitored:  []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Seen:       map[string]bool{"10.20.1.5": true},
		Attributed: map[string]bool{"10.20.1.6": true},
	}
	batch := []domain.Event{flow(1, "10.20.1.5", "10.20.1.1", 80), flow(2, "10.20.1.6", "10.20.1.1", 80),
		flow(3, "10.20.1.99", "10.20.1.1", 80), flow(4, "10.20.1.99", "10.20.1.1", 443), flow(5, "8.8.8.8", "10.20.1.5", 80)}
	f := byDetector(Run(batch, in))[NewDevice]
	if len(f) != 1 || f[0].SrcIP != "10.20.1.99" || f[0].EventID != 3 {
		t.Fatalf("%+v", f)
	}
}

func TestLabEgress(t *testing.T) {
	in := Inputs{LabNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")}}
	batch := []domain.Event{flow(1, "10.20.9.10", "10.20.9.11", 22), flow(2, "10.20.9.10", "1.1.1.1", 443),
		flow(3, "10.20.9.10", "224.0.0.251", 5353), flow(4, "10.20.1.10", "1.1.1.1", 443)}
	f := byDetector(Run(batch, in))[LabEgress]
	if len(f) != 1 || f[0].DstIP != "1.1.1.1" || f[0].Severity != "high" {
		t.Fatalf("%+v", f)
	}
}

func TestDNSAnomaly(t *testing.T) {
	q := func(name string) domain.Event {
		return domain.Event{ID: 1, Time: t0, Kind: "dns", SrcIP: "10.255.0.2", Details: map[string]string{"dns.type": "query", "dns.rrname": name}}
	}
	normal := []string{"api.github.com", "www.example.org", "pf-ng-ids-canary.parallelf.test", "a1b2c3.cdn.example.net"}
	for _, n := range normal {
		if f := byDetector(Run([]domain.Event{q(n)}, Inputs{}))[DNSAnomaly]; len(f) != 0 {
			t.Errorf("%s flagged: %+v", n, f)
		}
	}
	tunnel := []string{
		"mzxw6ytboi4dsnzrgq3dqmjxgezdgnbvgy3tqojqgezdg.t.exfil.example",
		strings.Repeat("a", 55) + ".exfil.example",
		"x9k2pq7v4m1z8w3r6t5y0u2i4o7p.exfil.example",
	}
	for _, n := range tunnel {
		f := byDetector(Run([]domain.Event{q(n)}, Inputs{}))[DNSAnomaly]
		if len(f) != 1 || f[0].Details["domain"] != "exfil.example" {
			t.Errorf("%s not flagged: %+v", n, f)
		}
	}
	answer := q(strings.Repeat("b", 60) + ".example.com")
	answer.Details["dns.type"] = "answer"
	if f := byDetector(Run([]domain.Event{answer}, Inputs{}))[DNSAnomaly]; len(f) != 0 {
		t.Error("answers are not queries")
	}
}

func TestPortScanAndScopes(t *testing.T) {
	scope := ngsensor.Scope{ID: "s1", Name: "vpn-sweep", CIDRs: []string{"10.255.0.0/24"}, IssuedAt: t0.Add(-time.Minute), ValidUntil: t0.Add(time.Hour)}
	in := Inputs{
		Vertical: []ScanCount{
			{Src: "10.255.0.2", Dst: "10.20.1.5", Distinct: 25, LastEventID: 9, LastSeen: t0},
			{Src: "10.255.0.2", Dst: "10.20.1.6", Distinct: 5, LastEventID: 9, LastSeen: t0},
			{Src: "10.20.1.1", Dst: "10.255.0.3", Distinct: 30, LastEventID: 9, LastSeen: t0},
		},
		Horizontal: []ScanCount{{Src: "10.255.0.2", Port: 22, Distinct: 21, LastEventID: 9, LastSeen: t0}},
		Scopes:     []ngsensor.Scope{scope},
	}
	f := byDetector(Run(nil, in))[PortScan]
	if len(f) != 3 {
		t.Fatalf("%+v", f)
	}
	sev := map[string]string{}
	for _, x := range f {
		sev[x.DedupeKey] = x.Severity
	}
	if sev["port_scan:v:10.255.0.2>10.20.1.5"] != "high" || sev["port_scan:v:10.20.1.1>10.255.0.3"] != "info" || sev["port_scan:h:10.255.0.2:22"] != "high" {
		t.Fatalf("%v", sev)
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaa") != 0 || Entropy("ab") != 1 {
		t.Fatal("entropy")
	}
}
