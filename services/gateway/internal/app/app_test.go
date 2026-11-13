package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/services/gateway/internal/config"
	"github.com/commonvtake/parallelf/services/gateway/internal/proxy"
	"github.com/commonvtake/parallelf/services/gateway/internal/status"
)

type tokenVerifier struct{}

func (tokenVerifier) Verify(_ context.Context, raw string) (*authn.Principal, error) {
	subject, role, ok := strings.Cut(raw, ":")
	if !ok {
		return nil, authn.ErrInvalidToken
	}
	return &authn.Principal{Subject: subject, Username: subject, Roles: []string{role}}, nil
}

type upstream struct {
	server *httptest.Server
	hits   atomic.Int64
	last   atomic.Pointer[http.Request]
	ready  atomic.Bool
}

func newUpstream(t *testing.T, name string, checks map[string]string) *upstream {
	t.Helper()
	u := &upstream{}
	u.ready.Store(true)
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			resp := httpx.HealthResponse{Status: "ok", Service: name, Version: "9.9.9", Checks: checks}
			code := http.StatusOK
			if !u.ready.Load() {
				resp.Status = "unavailable"
				code = http.StatusServiceUnavailable
			}
			httpx.WriteJSON(w, code, resp)
			return
		}
		u.hits.Add(1)
		u.last.Store(r.Clone(context.Background()))
		w.Header().Set("X-Request-ID", "upstream-generated-id")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Upstream", name)
		httpx.WriteJSON(w, http.StatusTeapot, map[string]string{"served_by": name, "path": r.URL.RequestURI()})
	}))
	t.Cleanup(u.server.Close)
	return u
}

type gatewayHarness struct {
	handler  http.Handler
	core, ai *upstream
	jwks     *httptest.Server
}

func newGateway(t *testing.T) *gatewayHarness {
	t.Helper()
	h := &gatewayHarness{
		core: newUpstream(t, "pf-core", map[string]string{"postgres": "ok"}),
		ai:   newUpstream(t, "pf-aid", nil),
		jwks: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
		})),
	}
	t.Cleanup(h.jwks.Close)

	mustURL := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	cfg := config.Config{
		CoreURL: mustURL(h.core.server.URL),
		AIURL:   mustURL(h.ai.server.URL),
		OIDC:    authn.OIDCSettings{Issuer: "http://issuer.test", JWKSURL: h.jwks.URL, Audience: "parallelf-api"},
	}
	h.handler = NewHandler(cfg, tokenVerifier{}, proxy.NewTransport(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h
}

func (h *gatewayHarness) get(path, token string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "203.0.113.7:51000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func TestGatewayHealthIsUnauthenticated(t *testing.T) {
	h := newGateway(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := h.get(path, "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d", path, rec.Code)
		}
		var body httpx.HealthResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Service != ServiceName {
			t.Errorf("%s body = %s", path, rec.Body.String())
		}
	}
}

func TestGatewayRejectsUnauthenticatedAPIRequestsBeforeProxying(t *testing.T) {
	h := newGateway(t)
	paths := []string{"/api/v1/core/projects", "/api/v1/ai/info", "/api/v1/system/status"}
	for _, path := range paths {
		for name, token := range map[string]string{"no token": "", "invalid token": "garbage"} {
			rec := h.get(path, token, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with %s = %d, want 401", path, name, rec.Code)
			}
		}
	}
	if h.core.hits.Load() != 0 || h.ai.hits.Load() != 0 {
		t.Errorf("unauthenticated requests reached an upstream (core=%d ai=%d)", h.core.hits.Load(), h.ai.hits.Load())
	}
}

func TestGatewayProxiesToOwningService(t *testing.T) {
	h := newGateway(t)

	rec := h.get("/api/v1/core/projects?limit=2", "user-1:viewer", map[string]string{
		"X-Forwarded-For": "10.0.0.1", // spoof attempt
		"X-Request-ID":    "client-request-0001",
	})
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the upstream's status passed through", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["served_by"] != "pf-core" || body["path"] != "/api/v1/core/projects?limit=2" {
		t.Errorf("body = %v, want path and query forwarded unchanged to core", body)
	}

	seen := h.core.last.Load()
	if got := seen.Header.Get("Authorization"); got != "Bearer user-1:viewer" {
		t.Errorf("upstream Authorization = %q, want the caller's token", got)
	}
	if got := seen.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Errorf("upstream X-Forwarded-For = %q, want only the address the gateway saw", got)
	}
	if got := seen.Header.Get("X-Request-ID"); got != "client-request-0001" {
		t.Errorf("upstream X-Request-ID = %q", got)
	}
	if got := rec.Header().Values("X-Request-ID"); len(got) != 1 || got[0] != "client-request-0001" {
		t.Errorf("response X-Request-ID = %v, want exactly the gateway's id", got)
	}
	if got := rec.Header().Values("X-Content-Type-Options"); len(got) != 1 {
		t.Errorf("X-Content-Type-Options = %v, want one value", got)
	}
	if rec.Header().Get("X-Upstream") != "pf-core" {
		t.Error("ordinary upstream headers must pass through")
	}

	if rec := h.get("/api/v1/ai/info", "user-1:viewer", nil); rec.Code != http.StatusTeapot || h.ai.hits.Load() != 1 {
		t.Errorf("ai route: status = %d, ai hits = %d", rec.Code, h.ai.hits.Load())
	}
	if h.core.hits.Load() != 1 {
		t.Errorf("core hits = %d, want 1", h.core.hits.Load())
	}
}

func TestGatewayReturnsProblemWhenUpstreamIsDown(t *testing.T) {
	h := newGateway(t)
	h.core.server.Close()

	rec := h.get("/api/v1/core/projects", "user-1:viewer", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var p httpx.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not a problem document: %s", rec.Body.String())
	}
	if p.Status != http.StatusBadGateway || p.RequestID == "" {
		t.Errorf("problem = %+v", p)
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Error("upstream address leaked to the client")
	}
}

func componentByName(report status.Report) map[string]status.Component {
	out := make(map[string]status.Component, len(report.Components))
	for _, c := range report.Components {
		out[c.Name] = c
	}
	return out
}

func TestSystemStatus(t *testing.T) {
	h := newGateway(t)

	rec := h.get("/api/v1/system/status", "user-1:viewer", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var report status.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != status.OK {
		t.Errorf("overall status = %q, want ok: %+v", report.Status, report.Components)
	}
	components := componentByName(report)
	for _, name := range []string{ServiceName, "core", "postgres", "ai", "identity-provider"} {
		if c, ok := components[name]; !ok || c.Status != status.OK {
			t.Errorf("component %q = %+v, want ok", name, c)
		}
	}
	if components["postgres"].ReportedBy != "core" || components["core"].Version != "9.9.9" {
		t.Errorf("core details not surfaced: %+v", components)
	}

	// One service becoming unready degrades the platform but not the endpoint.
	h.ai.ready.Store(false)
	h.jwks.Close()
	rec = h.get("/api/v1/system/status", "user-1:viewer", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status endpoint = %d while degraded, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	components = componentByName(report)
	if report.Status != status.Degraded || components["ai"].Status != status.Unavailable ||
		components["identity-provider"].Status != status.Unavailable || components["core"].Status != status.OK {
		t.Errorf("degraded report = %+v", report)
	}
}

func TestSystemStatusRequiresPlatformRole(t *testing.T) {
	h := newGateway(t)
	if rec := h.get("/api/v1/system/status", "user-1:not-a-platform-role", nil); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestGatewayUnknownRoute(t *testing.T) {
	h := newGateway(t)
	for _, path := range []string{"/", "/api/v1/unknown/x", "/api/v2/core/projects"} {
		if rec := h.get(path, "user-1:viewer", nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	if h.core.hits.Load() != 0 {
		t.Error("unknown route reached an upstream")
	}
}
