package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

const (
	alertID = "01900000-0000-7000-8000-0000000000a1"
	scopeID = "01900000-0000-7000-8000-0000000000b1"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// verifier maps tokens to principals: "<role>" signed in just now,
// "<role>-stale" an hour ago, "cli" a development token without auth_time.
type verifier struct{}

func (verifier) Verify(_ context.Context, token string) (*authn.Principal, error) {
	role, stale := strings.CutSuffix(token, "-stale")
	switch role {
	case "cli":
		return &authn.Principal{Subject: "sub-owner", Username: "owner", Roles: []string{"owner"}, ClientID: "dev-cli"}, nil
	case "owner", "viewer", "analyst", "operator":
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
	change  domain.AlertChange
	issued  domain.ScopeInput
	revoked bool
}

func (f *fakeStore) ChangeAlert(_ context.Context, id string, c domain.AlertChange, a domain.Actor) (domain.Alert, error) {
	f.change = c
	return domain.Alert{ID: id, Status: c.Status, StatusBy: a.Label()}, nil
}

func (f *fakeStore) IssueScope(_ context.Context, in domain.ScopeInput, _ domain.Actor) (domain.Scope, error) {
	f.issued = in
	return domain.Scope{Status: "active"}, nil
}

func (f *fakeStore) GetScope(_ context.Context, id string) (domain.Scope, error) {
	if id != scopeID {
		return domain.Scope{}, domain.ErrNotFound
	}
	s := domain.Scope{Status: "active"}
	s.ID, s.Name = scopeID, "vpn-inventory"
	return s, nil
}

func (f *fakeStore) RevokeScope(context.Context, string, domain.Actor) (domain.Scope, error) {
	f.revoked = true
	return domain.Scope{Status: "revoked"}, nil
}

func (f *fakeStore) ListAlerts(context.Context, domain.AlertFilter) ([]domain.Alert, error) {
	return nil, nil
}

func newServer(f *fakeStore) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := New(f, StepUp{MaxAuthAge: 15 * time.Minute, ExemptClients: []string{"dev-cli"}}, logger)
	a.now = func() time.Time { return now }
	mux := http.NewServeMux()
	a.Register(mux, authn.Require(verifier{}, logger))
	return httpx.Chain(mux, httpx.RequestID())
}

func call(h http.Handler, method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
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

func TestPermissions(t *testing.T) {
	f := &fakeStore{}
	h := newServer(f)
	if rec, _ := call(h, "GET", "/api/v1/network/alerts", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec, _ := call(h, "GET", "/api/v1/network/alerts", "viewer", ""); rec.Code != http.StatusOK {
		t.Fatalf("viewer reads alerts: %d", rec.Code)
	}
	body := `{"status":"acknowledged"}`
	if rec, _ := call(h, "POST", "/api/v1/network/alerts/"+alertID+"/status", "viewer", body); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer triage: %d", rec.Code)
	}
	if rec, _ := call(h, "POST", "/api/v1/network/alerts/"+alertID+"/status", "operator", body); rec.Code != http.StatusForbidden {
		t.Fatalf("operator triage: %d", rec.Code)
	}
	rec, out := call(h, "POST", "/api/v1/network/alerts/"+alertID+"/status", "analyst", body)
	if rec.Code != http.StatusOK || out["status_by"] != "analyst" {
		t.Fatalf("analyst triage: %d %v", rec.Code, out)
	}
	if rec, _ := call(h, "POST", "/api/v1/network/scopes", "analyst", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst issuing a scope: %d", rec.Code)
	}
	if rec, _ := call(h, "GET", "/api/v1/network/audit", "viewer", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer audit: %d", rec.Code)
	}
}

func TestAlertValidation(t *testing.T) {
	h := newServer(&fakeStore{})
	rec, out := call(h, "POST", "/api/v1/network/alerts/"+alertID+"/status", "analyst", `{"status":"suppressed","suppress_for":"2h"}`)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("suppression without a reason: %d %v", rec.Code, out)
	}
	if rec, _ := call(h, "POST", "/api/v1/network/alerts/"+alertID+"/status", "analyst", `{"status":"suppressed","suppress_for":"soon","reason":"x"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad duration: %d", rec.Code)
	}
	if rec, _ := call(h, "POST", "/api/v1/network/alerts/not-a-uuid/status", "analyst", `{"status":"closed"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("bad id: %d", rec.Code)
	}
	if rec, _ := call(h, "GET", "/api/v1/network/alerts?severity=urgent", "viewer", ""); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad severity: %d", rec.Code)
	}
}

func TestScopeStepUpAndConfirmation(t *testing.T) {
	f := &fakeStore{}
	h := newServer(f)
	body := `{"name":"vpn-inventory","cidrs":["10.255.0.0/24"],"techniques":["icmp-echo"],"authorization_note":"Owner-approved inventory."}`
	rec, out := call(h, "POST", "/api/v1/network/scopes", "owner-stale", body)
	if rec.Code != http.StatusForbidden || !strings.Contains(out["type"].(string), "reauthentication-required") {
		t.Fatalf("stale sign-in: %d %v", rec.Code, out)
	}
	if rec, _ := call(h, "POST", "/api/v1/network/scopes", "owner", body); rec.Code != http.StatusCreated || f.issued.Name != "vpn-inventory" {
		t.Fatalf("issue: %d", rec.Code)
	}
	if rec, _ := call(h, "POST", "/api/v1/network/scopes", "cli", body); rec.Code != http.StatusCreated {
		t.Fatalf("exempt development client: %d", rec.Code)
	}
	if rec, _ := call(h, "DELETE", "/api/v1/network/scopes/"+scopeID, "owner", ""); rec.Code != http.StatusPreconditionRequired || f.revoked {
		t.Fatalf("revoke without confirmation: %d", rec.Code)
	}
	if rec, _ := call(h, "DELETE", "/api/v1/network/scopes/"+scopeID+"?confirm=vpn-inventory", "owner", ""); rec.Code != http.StatusOK || !f.revoked {
		t.Fatalf("revoke: %d", rec.Code)
	}
}
