package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/commonvtake/parallelf/pkg/httpx"
)

type fakeVerifier map[string]*Principal

func (f fakeVerifier) Verify(_ context.Context, raw string) (*Principal, error) {
	if p, ok := f[raw]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("%w: signature mismatch for kid=secret-kid", ErrInvalidToken)
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc.def.ghi": "abc.def.ghi",
		"bearer abc":         "abc",
		"BEARER   abc  ":     "abc",
		"Basic abc":          "",
		"Bearer":             "",
		"Bearer ":            "",
		"":                   "",
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		got, ok := BearerToken(r)
		if got != want || ok != (want != "") {
			t.Errorf("BearerToken(%q) = %q, %v; want %q", header, got, ok, want)
		}
	}
}

func TestRequire(t *testing.T) {
	verifier := fakeVerifier{"good": {Subject: "u-1", Username: "owner", Roles: []string{"owner"}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var seen *Principal
	h := httpx.Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = PrincipalFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}), Require(verifier, logger))

	t.Run("valid token", func(t *testing.T) {
		seen = nil
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent || seen == nil || seen.Subject != "u-1" {
			t.Fatalf("status = %d, principal = %+v", rec.Code, seen)
		}
	})

	for name, header := range map[string]string{"missing": "", "invalid": "Bearer bad", "wrong scheme": "Basic Zm9v"} {
		t.Run(name, func(t *testing.T) {
			seen = nil
			req := httptest.NewRequest(http.MethodGet, "/secure", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if seen != nil {
				t.Error("handler ran for an unauthenticated request")
			}
			if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Errorf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
			}
			var p httpx.Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("body is not a problem document: %v", err)
			}
			if strings.Contains(rec.Body.String(), "secret-kid") {
				t.Error("verifier error detail leaked to the client")
			}
		})
	}
}

func TestPrincipalFromEmptyContext(t *testing.T) {
	if p, ok := PrincipalFrom(context.Background()); ok || p != nil {
		t.Errorf("PrincipalFrom(empty) = %+v, %v", p, ok)
	}
}
