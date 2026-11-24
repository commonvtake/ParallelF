package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

const (
	deviceID  = "01900000-0000-7000-8000-0000000000d1"
	policyID  = "01900000-0000-7000-8000-0000000000e1"
	unknownID = "01900000-0000-7000-8000-0000000000ff"
	goodKey   = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// verifier maps tokens to principals: "<role>" signed in just now,
// "<role>-stale" an hour ago.
type verifier struct{}

func (verifier) Verify(_ context.Context, token string) (*authn.Principal, error) {
	role, stale := strings.CutSuffix(token, "-stale")
	switch role {
	case "cli":
		// A development CLI token: no auth_time at all.
		return &authn.Principal{Subject: "sub-operator", Username: "operator", Roles: []string{"operator"}, ClientID: "dev-cli"}, nil
	case "owner", "viewer", "operator", "admin":
		at := now.Add(-time.Minute)
		if stale {
			at = now.Add(-time.Hour)
		}
		return &authn.Principal{Subject: "sub-" + role, Username: role, Roles: []string{role}, AuthTime: at, ClientID: "parallelf-dashboard"}, nil
	}
	return nil, authn.ErrInvalidToken
}

type fakeStore struct {
	Store
	device       domain.Device
	createdOwner domain.Owner
	activatedTo  time.Time
	revoked      bool
	policy       domain.PolicyInput
}

func (f *fakeStore) GetDevice(_ context.Context, id string) (domain.Device, error) {
	if id != f.device.ID {
		return domain.Device{}, domain.ErrNotFound
	}
	return f.device, nil
}

func (f *fakeStore) CreateDevice(_ context.Context, in domain.DeviceInput, owner domain.Owner, _ domain.Actor) (domain.Device, string, error) {
	f.createdOwner = owner
	return domain.Device{ID: deviceID, Name: in.Name, OwnerSubject: owner.Subject, Address: "10.255.0.10", Groups: owner.Groups, State: domain.StatePending}, "", nil
}

func (f *fakeStore) DeviceConfig(context.Context, domain.Device) (domain.ClientConfig, error) {
	return domain.ClientConfig{Address: "10.255.0.10/32", GatewayPublicKey: goodKey, Endpoint: "192.0.2.1:51820",
		AllowedIPs: []string{"10.255.0.0/22"}, PersistentKeepalive: 25}, nil
}

func (f *fakeStore) Activate(_ context.Context, _ string, until time.Time, _ domain.Actor) (domain.Device, error) {
	f.activatedTo = until
	d := f.device
	d.ActiveUntil = &until
	return d.Derive(now), nil
}

func (f *fakeStore) Revoke(context.Context, string, domain.Actor) (domain.Device, error) {
	f.revoked = true
	d := f.device
	d.State = domain.StateRevoked
	return d, nil
}

func (f *fakeStore) CreatePolicy(_ context.Context, in domain.PolicyInput, _ domain.Actor) (domain.Policy, error) {
	f.policy = in
	return domain.Policy{ID: policyID, Name: in.Name}, nil
}

var exempt []string

func newServer(t *testing.T, f *fakeStore) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := New(f, Activation{Default: 8 * time.Hour, Min: 30 * time.Second, Max: 12 * time.Hour, MaxAuthAge: 15 * time.Minute,
		ExemptClients: exempt},
		netip.MustParsePrefix("10.255.0.0/22"), logger)
	a.now = func() time.Time { return now }
	mux := http.NewServeMux()
	a.Register(mux, authn.Require(verifier{}, logger))
	return httpx.Chain(mux, httpx.RequestID())
}

func call(t *testing.T, h http.Handler, method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func ownersDevice() domain.Device {
	return domain.Device{ID: deviceID, Name: "laptop", OwnerSubject: "sub-operator", Address: "10.255.0.10", State: domain.StateEnrolled, ExpiresAt: now.Add(90 * 24 * time.Hour)}
}

func TestAuthenticationAndPermissions(t *testing.T) {
	h := newServer(t, &fakeStore{})
	if rec, _ := call(t, h, "GET", "/api/v1/vpn/devices/"+deviceID, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	body := `{"name":"phone","public_key":"` + goodKey + `"}`
	if rec, _ := call(t, h, "POST", "/api/v1/vpn/devices", "viewer", body); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer enrol: %d", rec.Code)
	}
	if rec, _ := call(t, h, "GET", "/api/v1/vpn/devices?scope=all", "operator", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("operator listing all: %d", rec.Code)
	}
	if rec, _ := call(t, h, "POST", "/api/v1/vpn/policies", "operator", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("operator policy: %d", rec.Code)
	}
}

func TestEnrolment(t *testing.T) {
	f := &fakeStore{}
	h := newServer(t, f)
	rec, out := call(t, h, "POST", "/api/v1/vpn/devices", "operator", `{"name":"Bad Name","public_key":"nope"}`)
	if rec.Code != http.StatusUnprocessableEntity || len(out["errors"].([]any)) != 2 {
		t.Fatalf("invalid: %d %v", rec.Code, out)
	}
	rec, out = call(t, h, "POST", "/api/v1/vpn/devices", "operator", `{"name":"phone","public_key":"`+goodKey+`"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %v", rec.Code, rec.Header())
	}
	cfg := out["config"].(map[string]any)
	if cfg["gateway_public_key"] != goodKey || cfg["persistent_keepalive"].(float64) != 25 {
		t.Fatalf("config %v", cfg)
	}
	if f.createdOwner.Subject != "sub-operator" || len(f.createdOwner.Groups) != 1 || f.createdOwner.Groups[0] != "operator" {
		t.Fatalf("owner %+v", f.createdOwner)
	}
	if strings.Contains(rec.Body.String(), "private") {
		t.Fatal("no private key may ever appear in a response")
	}
}

func TestOwnership(t *testing.T) {
	f := &fakeStore{device: ownersDevice()}
	h := newServer(t, f)
	if rec, _ := call(t, h, "GET", "/api/v1/vpn/devices/"+deviceID, "owner", ""); rec.Code != http.StatusOK {
		t.Fatalf("a manager sees any device: %d", rec.Code)
	}
	f.device.OwnerSubject = "sub-someone-else"
	if rec, _ := call(t, h, "GET", "/api/v1/vpn/devices/"+deviceID, "operator", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("another user's device must look missing: %d", rec.Code)
	}
	if rec, _ := call(t, h, "GET", "/api/v1/vpn/devices/not-an-id", "operator", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("malformed id: %d", rec.Code)
	}
}

func TestActivationNeedsTheOwnerAndARecentSignIn(t *testing.T) {
	f := &fakeStore{device: ownersDevice()}
	h := newServer(t, f)
	if rec, _ := call(t, h, "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "owner", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a manager may not activate someone else's device: %d", rec.Code)
	}
	rec, out := call(t, h, "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "operator-stale", "")
	if rec.Code != http.StatusForbidden || out["type"] != "https://parallelf.dev/problems/reauthentication-required" {
		t.Fatalf("stale sign-in: %d %v", rec.Code, out)
	}
	if rec, _ := call(t, h, "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "operator", `{"ttl_seconds":5}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("too short: %d", rec.Code)
	}
	rec, out = call(t, h, "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "operator", `{"ttl_seconds":600}`)
	if rec.Code != http.StatusOK || out["active"] != true || !f.activatedTo.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("activate: %d %v %v", rec.Code, out, f.activatedTo)
	}
	if rec, _ := call(t, h, "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "operator", ""); rec.Code != http.StatusOK || !f.activatedTo.Equal(now.Add(8*time.Hour)) {
		t.Fatalf("default length: %d %v", rec.Code, f.activatedTo)
	}
}

func TestStepUpExemptionIsPerClient(t *testing.T) {
	f := &fakeStore{device: ownersDevice()}
	if rec, _ := call(t, newServer(t, f), "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "cli", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a token without auth_time must be refused: %d", rec.Code)
	}
	exempt = []string{"dev-cli"}
	defer func() { exempt = nil }()
	if rec, _ := call(t, newServer(t, f), "POST", "/api/v1/vpn/devices/"+deviceID+"/activate", "cli", ""); rec.Code != http.StatusOK {
		t.Fatalf("an exempt development client: %d", rec.Code)
	}
}

func TestRevocationNeedsConfirmation(t *testing.T) {
	f := &fakeStore{device: ownersDevice()}
	h := newServer(t, f)
	rec, out := call(t, h, "DELETE", "/api/v1/vpn/devices/"+deviceID, "operator", "")
	if rec.Code != http.StatusPreconditionRequired || f.revoked || out["type"] != "https://parallelf.dev/problems/confirmation-required" {
		t.Fatalf("unconfirmed: %d %v", rec.Code, out)
	}
	if rec, _ := call(t, h, "DELETE", "/api/v1/vpn/devices/"+deviceID+"?confirm=laptop", "operator", ""); rec.Code != http.StatusOK || !f.revoked {
		t.Fatalf("confirmed: %d", rec.Code)
	}
}

func TestPolicyValidation(t *testing.T) {
	f := &fakeStore{}
	h := newServer(t, f)
	rec, _ := call(t, h, "POST", "/api/v1/vpn/policies", "admin",
		`{"name":"ssh","priority":10,"action":"allow","groups":["ops"],"destinations":["10.255.0.0/24"],"protocol":"tcp","ports":["22"]}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a destination inside the tunnel must be refused: %d", rec.Code)
	}
	rec, _ = call(t, h, "POST", "/api/v1/vpn/policies", "admin",
		`{"name":"ssh","priority":10,"action":"allow","groups":["ops"],"destinations":["10.20.1.9/24","platform"],"protocol":"tcp","ports":["22"]}`)
	if rec.Code != http.StatusCreated || f.policy.Destinations[0] != "10.20.1.0/24" {
		t.Fatalf("create: %d %+v", rec.Code, f.policy)
	}
}
