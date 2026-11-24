package sensorapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

type fakeStore struct {
	registered []domain.SensorRegistration
	ingested   []ngsensor.IngestRequest
}

func (f *fakeStore) RegisterSensor(_ context.Context, r domain.SensorRegistration) (domain.Sensor, error) {
	f.registered = append(f.registered, r)
	return domain.Sensor{ID: "s-1", Name: r.Name, Engine: r.Engine}, nil
}

func (f *fakeStore) AuthenticateSensor(_ context.Context, h []byte) (domain.Sensor, error) {
	for _, r := range f.registered {
		if bytes.Equal(r.TokenHash, h) {
			return domain.Sensor{ID: "s-1", Name: r.Name}, nil
		}
	}
	return domain.Sensor{}, domain.ErrUnauthorizedSens
}

func (f *fakeStore) Ingest(_ context.Context, _ domain.Sensor, req ngsensor.IngestRequest) (int, error) {
	f.ingested = append(f.ingested, req)
	return len(req.Events), nil
}

func (f *fakeStore) ActiveScopes(context.Context) ([]ngsensor.SignedScope, error) {
	return []ngsensor.SignedScope{{Document: "ZG9j", Signature: "c2ln"}}, nil
}

func call(t *testing.T, h http.Handler, path, token string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ngsensor.VersionHeader, ngsensor.Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestRegisterAndIngest(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	st := &fakeStore{}
	api := New(st, "join-token-join-token-123", pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	api.Register(mux)

	if code, _ := call(t, mux, ngsensor.PathRegister, "wrong", ngsensor.RegisterRequest{Name: "host"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong join token: %d", code)
	}
	code, body := call(t, mux, ngsensor.PathRegister, "join-token-join-token-123", ngsensor.RegisterRequest{Name: "host", Engine: "Suricata 7.0.3"})
	if code != http.StatusOK {
		t.Fatalf("register: %d %s", code, body)
	}
	var reg ngsensor.RegisterResponse
	_ = json.Unmarshal(body, &reg)
	if !strings.HasPrefix(reg.Credential, "pfng_") || reg.ScopePublicKey == "" {
		t.Fatalf("%+v", reg)
	}
	if string(st.registered[0].TokenHash) == reg.Credential {
		t.Fatal("the credential must be stored hashed")
	}

	now := time.Now().UTC()
	good := ngsensor.Event{Time: now, Kind: "flow", SrcIP: "10.255.0.2", DstIP: "10.255.0.1", DstPort: 80, RawSHA256: strings.Repeat("a", 64),
		Details: map[string]string{"flow.state": "established", "Bad Key!": "x"}}
	badIP := good
	badIP.SrcIP, badIP.RawSHA256 = "not-an-ip", strings.Repeat("b", 64)
	badKind := good
	badKind.Kind, badKind.RawSHA256 = "exploit", strings.Repeat("c", 64)
	future := good
	future.Time, future.RawSHA256 = now.Add(48*time.Hour), strings.Repeat("d", 64)
	code, body = call(t, mux, ngsensor.PathIngest, reg.Credential, ngsensor.IngestRequest{Engine: "Suricata", Interfaces: []string{"wg-pf0", "bad iface"},
		Events: []ngsensor.Event{good, badIP, badKind, future}})
	if code != http.StatusOK {
		t.Fatalf("ingest: %d %s", code, body)
	}
	var ing ngsensor.IngestResponse
	_ = json.Unmarshal(body, &ing)
	if ing.Accepted != 1 || len(ing.Scopes) != 1 {
		t.Fatalf("%+v", ing)
	}
	got := st.ingested[0]
	if len(got.Events) != 1 || len(got.Interfaces) != 1 || got.Events[0].Details["Bad Key!"] != "" {
		t.Fatalf("%+v", got)
	}
	if code, _ := call(t, mux, ngsensor.PathIngest, "pfng_unknown", ngsensor.IngestRequest{}); code != http.StatusUnauthorized {
		t.Fatalf("unknown credential: %d", code)
	}
}

func TestSanitizeTruncatesFields(t *testing.T) {
	e, ok := Sanitize(ngsensor.Event{Time: time.Now(), Kind: "dns", RawSHA256: strings.Repeat("0", 64),
		Details: map[string]string{"dns.rrname": strings.Repeat("x", 4000)}}, time.Now())
	if !ok || len(e.Details["dns.rrname"]) != ngsensor.MaxFieldBytes {
		t.Fatalf("%v %d", ok, len(e.Details["dns.rrname"]))
	}
}
