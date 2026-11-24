package ngsensor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func scope() Scope {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	return Scope{ID: "s1", Name: "lab", CIDRs: []string{"10.255.0.0/30"}, Techniques: []string{TechniqueTCPConnect},
		Ports: []int{8000}, RatePPS: 10, IssuedAt: now, ValidUntil: now.Add(time.Hour)}
}

func TestGuards(t *testing.T) {
	if err := CheckGuards(scope()); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Scope){
		"public":        func(s *Scope) { s.CIDRs = []string{"8.8.8.0/24"} },
		"too large":     func(s *Scope) { s.CIDRs = []string{"10.0.0.0/16"} },
		"straddles":     func(s *Scope) { s.CIDRs = []string{"172.15.255.0/22"} },
		"ipv6":          func(s *Scope) { s.CIDRs = []string{"fd00::/120"} },
		"syn scan":      func(s *Scope) { s.Techniques = []string{"syn-scan"} },
		"no ports":      func(s *Scope) { s.Ports = nil },
		"fast":          func(s *Scope) { s.RatePPS = 1000 },
		"invalid port":  func(s *Scope) { s.Ports = []int{70000} },
		"no techniques": func(s *Scope) { s.Techniques = nil },
	}
	for name, mutate := range bad {
		s := scope()
		mutate(&s)
		if CheckGuards(s) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := scope()
	signed, err := Sign(s, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(signed, pub, s.IssuedAt.Add(time.Minute))
	if err != nil || got.ID != "s1" {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if _, err := Verify(signed, pub, s.ValidUntil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(signed, other, s.IssuedAt); err == nil {
		t.Fatal("a scope signed by another key must be refused")
	}
	// Widening the document after signing breaks the signature.
	doc, _ := base64.StdEncoding.DecodeString(signed.Document)
	tampered := strings.Replace(string(doc), "10.255.0.0/30", "10.255.0.0/22", 1)
	signed.Document = base64.StdEncoding.EncodeToString([]byte(tampered))
	if _, err := Verify(signed, pub, s.IssuedAt); err == nil {
		t.Fatal("a tampered scope must be refused")
	}
	// A validly signed scope that breaks a guard is still refused.
	wide := scope()
	wide.CIDRs = []string{"8.8.8.0/24"}
	signedWide, _ := Sign(wide, priv)
	if _, err := Verify(signedWide, pub, s.IssuedAt); err == nil {
		t.Fatal("guards apply to signed scopes too")
	}
}
