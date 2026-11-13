package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/services/core/internal/projects"
)

// tokenVerifier treats the bearer token as "<subject>:<role>".
type tokenVerifier struct{}

func (tokenVerifier) Verify(_ context.Context, raw string) (*authn.Principal, error) {
	subject, role, ok := strings.Cut(raw, ":")
	if !ok {
		return nil, authn.ErrInvalidToken
	}
	return &authn.Principal{
		Subject: subject, Username: subject, Email: subject + "@parallelf.test",
		Roles: []string{role, "default-roles-parallelf"},
	}, nil
}

type passthroughEncoder struct{}

func (passthroughEncoder) ProjectCreated(p projects.Project) (projects.OutboxEvent, error) {
	return projects.OutboxEvent{ID: ids.NewV7(), Type: "created", Subject: p.ID}, nil
}

func (passthroughEncoder) ProjectDeleted(p projects.Project, _ string, _ time.Time) (projects.OutboxEvent, error) {
	return projects.OutboxEvent{ID: ids.NewV7(), Type: "deleted", Subject: p.ID}, nil
}

type harness struct {
	t       *testing.T
	handler http.Handler
	store   *projects.MemoryStore
}

func newHarness(t *testing.T, checks map[string]httpx.Check) *harness {
	t.Helper()
	store := projects.NewMemoryStore()
	svc := projects.NewService(store, passthroughEncoder{}, ids.NewV7, time.Now)
	return &harness{
		t:     t,
		store: store,
		handler: NewHandler(Dependencies{
			Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			Verifier:    tokenVerifier{},
			Projects:    svc,
			ReadyChecks: checks,
		}),
	}
}

func (h *harness) do(method, path, token, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("response is not JSON (%d): %v\n%s", rec.Code, err, rec.Body.String())
	}
	return v
}

func TestHealthEndpointsNeedNoToken(t *testing.T) {
	h := newHarness(t, map[string]httpx.Check{"postgres": func(context.Context) error { return nil }})
	if rec := h.do(http.MethodGet, "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d", rec.Code)
	}
	rec := h.do(http.MethodGet, "/readyz", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d", rec.Code)
	}
	if got := decode[httpx.HealthResponse](t, rec); got.Service != ServiceName || got.Checks["postgres"] != "ok" {
		t.Errorf("/readyz body = %+v", got)
	}

	down := newHarness(t, map[string]httpx.Check{"postgres": func(context.Context) error { return errors.New("down") }})
	if rec := down.do(http.MethodGet, "/readyz", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz with failing database = %d, want 503", rec.Code)
	}
}

func TestEveryAPIRouteRequiresAuthentication(t *testing.T) {
	h := newHarness(t, nil)
	id := ids.NewV7()
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/core/me"},
		{http.MethodGet, "/api/v1/core/projects"},
		{http.MethodPost, "/api/v1/core/projects"},
		{http.MethodGet, "/api/v1/core/projects/" + id},
		{http.MethodDelete, "/api/v1/core/projects/" + id},
	}
	for _, rt := range routes {
		for name, token := range map[string]string{"no token": "", "invalid token": "garbage"} {
			rec := h.do(rt.method, rt.path, token, "")
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with %s = %d, want 401", rt.method, rt.path, name, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("%s %s: Content-Type = %q", rt.method, rt.path, ct)
			}
		}
	}
}

func TestRoleMatrix(t *testing.T) {
	type expectation struct{ read, write int }
	roles := map[string]expectation{
		"owner":          {http.StatusOK, http.StatusCreated},
		"admin":          {http.StatusOK, http.StatusCreated},
		"operator":       {http.StatusOK, http.StatusForbidden},
		"analyst":        {http.StatusOK, http.StatusForbidden},
		"lab-researcher": {http.StatusOK, http.StatusForbidden},
		"viewer":         {http.StatusOK, http.StatusForbidden},
		"unknown-role":   {http.StatusForbidden, http.StatusForbidden},
	}
	for role, want := range roles {
		t.Run(role, func(t *testing.T) {
			h := newHarness(t, nil)
			token := "user-1:" + role

			if rec := h.do(http.MethodGet, "/api/v1/core/projects", token, ""); rec.Code != want.read {
				t.Errorf("list = %d, want %d", rec.Code, want.read)
			}
			rec := h.do(http.MethodPost, "/api/v1/core/projects", token, `{"slug":"demo-lab","name":"Demo"}`)
			if rec.Code != want.write {
				t.Errorf("create = %d, want %d", rec.Code, want.write)
			}

			// Seed a project as owner, then try to delete it with this role.
			seed := h.do(http.MethodPost, "/api/v1/core/projects", "root:owner", `{"slug":"seeded","name":"Seeded"}`)
			id := decode[projects.Project](t, seed).ID
			wantDelete := http.StatusForbidden
			if want.write == http.StatusCreated {
				wantDelete = http.StatusNoContent
			}
			if rec := h.do(http.MethodDelete, "/api/v1/core/projects/"+id, token, ""); rec.Code != wantDelete {
				t.Errorf("delete = %d, want %d", rec.Code, wantDelete)
			}
		})
	}
}

func TestMeReturnsPlatformRolesAndPermissions(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do(http.MethodGet, "/api/v1/core/me", "user-9:viewer", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	type meBody struct {
		Subject     string   `json:"subject"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	me := decode[meBody](t, rec)
	if me.Subject != "user-9" || len(me.Roles) != 1 || me.Roles[0] != "viewer" {
		t.Errorf("me = %+v, want only the platform role", me)
	}
	if len(me.Permissions) == 0 {
		t.Error("no permissions returned for viewer")
	}
}

func TestProjectLifecycle(t *testing.T) {
	h := newHarness(t, nil)
	admin := "admin-1:admin"

	rec := h.do(http.MethodPost, "/api/v1/core/projects", admin,
		`{"slug":"demo-lab","name":" Demo lab ","description":"First project"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	created := decode[projects.Project](t, rec)
	if !ids.IsUUID(created.ID) || created.Name != "Demo lab" || created.CreatedBy != "admin-1" {
		t.Errorf("created = %+v", created)
	}
	if loc := rec.Header().Get("Location"); loc != "/api/v1/core/projects/"+created.ID {
		t.Errorf("Location = %q", loc)
	}
	if rec.Header().Get(httpx.RequestIDHeader) == "" {
		t.Error("response has no X-Request-ID")
	}
	if len(h.store.Outbox) != 1 {
		t.Errorf("outbox has %d events after create, want 1", len(h.store.Outbox))
	}

	if rec := h.do(http.MethodPost, "/api/v1/core/projects", admin, `{"slug":"demo-lab","name":"Again"}`); rec.Code != http.StatusConflict {
		t.Errorf("duplicate slug = %d, want 409", rec.Code)
	}

	rec = h.do(http.MethodGet, "/api/v1/core/projects/"+created.ID, "viewer-1:viewer", "")
	if rec.Code != http.StatusOK || decode[projects.Project](t, rec).Slug != "demo-lab" {
		t.Errorf("get = %d %s", rec.Code, rec.Body.String())
	}

	rec = h.do(http.MethodGet, "/api/v1/core/projects", "viewer-1:viewer", "")
	if page := decode[projects.Page](t, rec); len(page.Items) != 1 || page.NextCursor != "" {
		t.Errorf("list = %+v", page)
	}

	if rec := h.do(http.MethodDelete, "/api/v1/core/projects/"+created.ID, admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/api/v1/core/projects/"+created.ID, admin, ""); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
	if rec := h.do(http.MethodDelete, "/api/v1/core/projects/"+created.ID, admin, ""); rec.Code != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", rec.Code)
	}
	if len(h.store.Outbox) != 2 {
		t.Errorf("outbox has %d events after delete, want 2", len(h.store.Outbox))
	}
}

func TestCreateProjectValidation(t *testing.T) {
	h := newHarness(t, nil)
	admin := "admin-1:admin"
	cases := []struct {
		name, body string
		want       int
		field      string
	}{
		{"bad slug", `{"slug":"Bad Slug","name":"x"}`, http.StatusUnprocessableEntity, "slug"},
		{"missing name", `{"slug":"good-slug"}`, http.StatusUnprocessableEntity, "name"},
		{"unknown field", `{"slug":"good-slug","name":"x","owner":"me"}`, http.StatusBadRequest, ""},
		{"malformed json", `{"slug":`, http.StatusBadRequest, ""},
		{"array body", `[]`, http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do(http.MethodPost, "/api/v1/core/projects", admin, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			p := decode[httpx.Problem](t, rec)
			if tc.field != "" && (len(p.Errors) == 0 || p.Errors[0].Field != tc.field) {
				t.Errorf("errors = %+v, want field %q", p.Errors, tc.field)
			}
		})
	}
	if len(h.store.Outbox) != 0 {
		t.Errorf("rejected requests produced %d events", len(h.store.Outbox))
	}

	t.Run("wrong content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/core/projects", strings.NewReader(`{"slug":"abc","name":"x"}`))
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		big := fmt.Sprintf(`{"slug":"abc","name":"x","description":"%s"}`, bytes.Repeat([]byte("a"), maxBodyBytes))
		rec := h.do(http.MethodPost, "/api/v1/core/projects", admin, big)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", rec.Code)
		}
	})
}

func TestListProjectsQueryValidationAndPaging(t *testing.T) {
	h := newHarness(t, nil)
	admin := "admin-1:admin"
	for i := range 3 {
		rec := h.do(http.MethodPost, "/api/v1/core/projects", admin, fmt.Sprintf(`{"slug":"proj-%d","name":"P"}`, i))
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed %d = %d", i, rec.Code)
		}
	}

	for _, query := range []string{"limit=0", "limit=201", "limit=abc", "cursor=not-a-uuid"} {
		if rec := h.do(http.MethodGet, "/api/v1/core/projects?"+query, admin, ""); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("?%s = %d, want 422", query, rec.Code)
		}
	}

	first := decode[projects.Page](t, h.do(http.MethodGet, "/api/v1/core/projects?limit=2", admin, ""))
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}
	second := decode[projects.Page](t, h.do(http.MethodGet, "/api/v1/core/projects?limit=2&cursor="+first.NextCursor, admin, ""))
	if len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].Slug != "proj-2" {
		t.Errorf("second page = %+v", second)
	}
}

func TestUnknownRoutesAndMalformedIDsReturnProblem404(t *testing.T) {
	h := newHarness(t, nil)
	for _, path := range []string{"/", "/api/v1/core/unknown", "/api/v1/core/projects/not-a-uuid"} {
		rec := h.do(http.MethodGet, path, "admin-1:admin", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
			continue
		}
		if p := decode[httpx.Problem](t, rec); p.Status != http.StatusNotFound || p.RequestID == "" {
			t.Errorf("GET %s problem = %+v", path, p)
		}
	}
}
