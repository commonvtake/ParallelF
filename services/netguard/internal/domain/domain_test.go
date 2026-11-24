package domain

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var owned = []netip.Prefix{netip.MustParsePrefix("10.255.0.0/22"), netip.MustParsePrefix("10.20.0.0/16")}

func fieldCodes(err error) map[string]string {
	var v *ValidationError
	out := map[string]string{}
	if errors.As(err, &v) {
		for _, e := range v.Errors {
			out[e.Field] = e.Code
		}
	}
	return out
}

func TestBuildScope(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	s, err := BuildScope(ScopeInput{Name: "vpn-sweep", CIDRs: []string{"10.255.0.0/24"}, Techniques: []string{"icmp-echo", "tcp-connect"},
		Ports: []int{443, 22, 22}, Duration: "30m", AuthorizationNote: "Owner-approved inventory of my VPN devices."}, "id-1", now, owned)
	if err != nil {
		t.Fatal(err)
	}
	if s.RatePPS != 20 || len(s.Ports) != 2 || s.Ports[0] != 22 || !s.ValidUntil.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("scope %+v", s)
	}

	cases := map[string]struct {
		in    ScopeInput
		field string
		code  string
	}{
		"not owned":     {ScopeInput{Name: "lan-sweep", CIDRs: []string{"192.168.1.0/24"}, Techniques: []string{"icmp-echo"}, AuthorizationNote: "my home network please"}, "cidrs", "not_owned"},
		"public range":  {ScopeInput{Name: "internet", CIDRs: []string{"8.8.8.0/24"}, Techniques: []string{"icmp-echo"}, AuthorizationNote: "this must be refused"}, "cidrs", "not_owned"},
		"too large":     {ScopeInput{Name: "too-big", CIDRs: []string{"10.20.0.0/16"}, Techniques: []string{"icmp-echo"}, AuthorizationNote: "a sixteen is too large"}, "cidrs", "guard"},
		"syn scan":      {ScopeInput{Name: "syn-scan", CIDRs: []string{"10.20.1.0/24"}, Techniques: []string{"tcp-syn"}, AuthorizationNote: "a technique we never run"}, "cidrs", "guard"},
		"no note":       {ScopeInput{Name: "no-note", CIDRs: []string{"10.20.1.0/24"}, Techniques: []string{"icmp-echo"}}, "authorization_note", "length"},
		"too long":      {ScopeInput{Name: "long-one", CIDRs: []string{"10.20.1.0/24"}, Techniques: []string{"icmp-echo"}, Duration: "48h", AuthorizationNote: "longer than a day"}, "duration", "range"},
		"rate too high": {ScopeInput{Name: "fast-one", CIDRs: []string{"10.20.1.0/24"}, Techniques: []string{"icmp-echo"}, RatePPS: 1000, AuthorizationNote: "too many packets"}, "cidrs", "guard"},
	}
	for name, c := range cases {
		_, err := BuildScope(c.in, "x", now, owned)
		if got := fieldCodes(err)[c.field]; got != c.code {
			t.Errorf("%s: %s = %q, want %q (%v)", name, c.field, got, c.code, err)
		}
	}
}

func TestTransitions(t *testing.T) {
	if !CanTransitionAlert(AlertOpen, AlertAcknowledged) || CanTransitionAlert(AlertClosed, AlertOpen) {
		t.Fatal("alert transitions")
	}
	if !CanTransitionIncident(IncidentResolved, IncidentInvestigating) || CanTransitionIncident(IncidentOpen, IncidentOpen) {
		t.Fatal("incident transitions")
	}
}

func TestValidateAlertChange(t *testing.T) {
	if err := ValidateAlertChange(AlertChange{Status: AlertSuppressed, SuppressFor: time.Hour}); fieldCodes(err)["reason"] != "required" {
		t.Fatalf("suppression needs a reason: %v", err)
	}
	if err := ValidateAlertChange(AlertChange{Status: AlertSuppressed, SuppressFor: 40 * 24 * time.Hour, Reason: "x"}); fieldCodes(err)["suppress_for"] != "range" {
		t.Fatalf("suppression is bounded: %v", err)
	}
	if err := ValidateAlertChange(AlertChange{Status: AlertClosed, Reason: "false positive"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateEvidence(t *testing.T) {
	if err := ValidateEvidence(EvidenceInput{Kind: "event", Name: "flow", Ref: "12"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvidence(EvidenceInput{Kind: "event", Name: "flow", Ref: "12", Content: []byte("x")}); fieldCodes(err)["content"] != "forbidden" {
		t.Fatal("captured evidence cannot carry client content")
	}
	if err := ValidateEvidence(EvidenceInput{Kind: "file", Name: "capture.pcap", Content: []byte{1}, MediaType: "bad"}); fieldCodes(err)["media_type"] != "format" {
		t.Fatal("file needs a media type")
	}
}
