package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, rec.Body.String())
	}
	return v
}

func TestWriteProblem(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, r, Unprocessable("Invalid project.", FieldError{Field: "slug", Code: "format"}))
	}), RequestID())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/core/projects", nil))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q", ct)
	}
	p := decodeBody[Problem](t, rec)
	if p.Type != ProblemTypeBase+"validation" || p.Status != 422 || p.Instance != "/api/v1/core/projects" {
		t.Errorf("unexpected problem: %+v", p)
	}
	if p.RequestID == "" || p.RequestID != rec.Header().Get(RequestIDHeader) {
		t.Errorf("request_id %q does not match header %q", p.RequestID, rec.Header().Get(RequestIDHeader))
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "slug" {
		t.Errorf("errors = %+v", p.Errors)
	}
}

func TestRequestIDAcceptsValidAndReplacesInvalid(t *testing.T) {
	var seen string
	h := Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
	}), RequestID())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "client-supplied-id-1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "client-supplied-id-1" {
		t.Errorf("valid inbound id replaced: %q", seen)
	}

	for _, bad := range []string{"short", "has space in it", "inject\r\nX-Evil: 1", strings.Repeat("a", 65)} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(RequestIDHeader, bad)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if seen == bad || seen == "" {
			t.Errorf("invalid inbound id %q was not replaced (got %q)", bad, seen)
		}
		if rec.Header().Get(RequestIDHeader) != seen {
			t.Errorf("response header %q != context id %q", rec.Header().Get(RequestIDHeader), seen)
		}
	}
}

func TestRecoverReturnsProblemAndLogs(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), RequestID(), Recover(logger))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if p := decodeBody[Problem](t, rec); strings.Contains(p.Detail, "boom") {
		t.Error("panic value leaked into the response body")
	}
	if !strings.Contains(logs.String(), "boom") {
		t.Error("panic value was not logged")
	}
}

func TestAccessLogRecordsStatus(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hi"))
	}), AccessLog(logger))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/brew", nil))

	var rec map[string]any
	if err := json.Unmarshal(logs.Bytes(), &rec); err != nil {
		t.Fatalf("access log is not JSON: %v", err)
	}
	if rec["status"] != float64(http.StatusTeapot) || rec["path"] != "/brew" || rec["bytes"] != float64(2) {
		t.Errorf("unexpected access log record: %v", rec)
	}
}

func TestDecodeJSON(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}
	cases := []struct {
		name        string
		contentType string
		payload     string
		limit       int64
		wantStatus  int
	}{
		{"valid", "application/json", `{"name":"a"}`, 1024, 0},
		{"valid with charset", "application/json; charset=utf-8", `{"name":"a"}`, 1024, 0},
		{"wrong content type", "text/plain", `{"name":"a"}`, 1024, http.StatusUnsupportedMediaType},
		{"unknown field", "application/json", `{"name":"a","extra":1}`, 1024, http.StatusBadRequest},
		{"malformed", "application/json", `{"name":`, 1024, http.StatusBadRequest},
		{"trailing data", "application/json", `{"name":"a"}{"name":"b"}`, 1024, http.StatusBadRequest},
		{"too large", "application/json", `{"name":"` + strings.Repeat("a", 200) + `"}`, 64, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *Problem
			h := Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				var b body
				got = DecodeJSON(r, &b)
			}), MaxBody(tc.limit))

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.payload))
			req.Header.Set("Content-Type", tc.contentType)
			h.ServeHTTP(httptest.NewRecorder(), req)

			switch {
			case tc.wantStatus == 0 && got != nil:
				t.Errorf("unexpected problem: %+v", got)
			case tc.wantStatus != 0 && (got == nil || got.Status != tc.wantStatus):
				t.Errorf("problem = %+v, want status %d", got, tc.wantStatus)
			}
		})
	}
}

func TestHealthEndpoints(t *testing.T) {
	health := NewHealth("pf-test", "1.0.0", discardLogger())
	mux := http.NewServeMux()
	health.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d", rec.Code)
	}
	if got := decodeBody[HealthResponse](t, rec); got.Status != "ok" || got.Service != "pf-test" || got.Version != "1.0.0" {
		t.Errorf("/healthz body = %+v", got)
	}

	health.AddCheck("postgres", func(context.Context) error { return nil })
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d with passing check", rec.Code)
	}

	health.AddCheck("broker", func(context.Context) error { return errors.New("dial tcp 10.0.0.5:4222: refused") })
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d with failing check", rec.Code)
	}
	got := decodeBody[HealthResponse](t, rec)
	if got.Status != "unavailable" || got.Checks["postgres"] != "ok" || got.Checks["broker"] != "unavailable" {
		t.Errorf("/readyz body = %+v", got)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Error("readiness response leaked the internal error text")
	}

	// A failing readiness check must not affect liveness.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d while a dependency is down", rec.Code)
	}
}

func TestRunShutsDownGracefully(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, ServerOptions{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), Logger: discardLogger()})
	}()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v after cancellation", err)
	}
}

func TestProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	if err := Probe(context.Background(), ok.URL); err != nil {
		t.Errorf("Probe(ok) = %v", err)
	}
	if err := Probe(context.Background(), bad.URL); err == nil {
		t.Error("Probe(503) = nil, want error")
	}
}
