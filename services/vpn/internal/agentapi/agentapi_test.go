package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

const join = "join-token-that-is-long-enough"

type fakeStore struct {
	mu       sync.Mutex
	hash     []byte
	revision int64
	changed  chan struct{}
	synced   vpnagent.SyncRequest
}

func (f *fakeStore) RegisterGateway(_ context.Context, r domain.GatewayRegistration) (domain.Gateway, error) {
	f.hash = r.TokenHash
	return domain.Gateway{ID: "gw-1", Name: r.Name}, nil
}

func (f *fakeStore) AuthenticateGateway(_ context.Context, h []byte) (domain.Gateway, error) {
	if !bytes.Equal(h, f.hash) {
		return domain.Gateway{}, domain.ErrUnauthorizedGW
	}
	return domain.Gateway{ID: "gw-1"}, nil
}

func (f *fakeStore) Sync(_ context.Context, _ domain.Gateway, req vpnagent.SyncRequest) error {
	f.synced = req
	return nil
}

func (f *fakeStore) DesiredState(context.Context, domain.Gateway) (vpnagent.SyncResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return vpnagent.SyncResponse{GatewayID: "gw-1", Revision: f.revision}, nil
}

func (f *fakeStore) Revision(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revision, nil
}

func (f *fakeStore) Changed() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.changed
}

func (f *fakeStore) bump() {
	f.mu.Lock()
	f.revision++
	close(f.changed)
	f.changed = make(chan struct{})
	f.mu.Unlock()
}

func post(h http.Handler, path, token string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(vpnagent.VersionHeader, vpnagent.Version)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRegisterAndLongPoll(t *testing.T) {
	f := &fakeStore{revision: 5, changed: make(chan struct{})}
	a := New(f, join, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	a.Register(mux)

	reg := vpnagent.RegisterRequest{Name: "gw", PublicKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", Endpoint: "192.0.2.1:51820", ListenPort: 51820}
	if rec := post(mux, vpnagent.PathRegister, "wrong", reg); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong join token: %d", rec.Code)
	}
	rec := post(mux, vpnagent.PathRegister, join, reg)
	var resp vpnagent.RegisterResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Credential == "" {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	if bytes.Contains(f.hash, []byte(resp.Credential)) || !bytes.Equal(f.hash, HashToken(resp.Credential)) {
		t.Fatal("only the credential's hash may be stored")
	}
	if rec := post(mux, vpnagent.PathSync, "pfgw_unknown", vpnagent.SyncRequest{}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown credential: %d", rec.Code)
	}

	// Behind: answered at once.
	start := time.Now()
	rec = post(mux, vpnagent.PathSync, resp.Credential, vpnagent.SyncRequest{Revision: 4, WaitSeconds: 10})
	if rec.Code != http.StatusOK || time.Since(start) > time.Second {
		t.Fatalf("behind: %d after %s", rec.Code, time.Since(start))
	}

	// Up to date: held until the state changes.
	go func() { time.Sleep(200 * time.Millisecond); f.bump() }()
	start = time.Now()
	rec = post(mux, vpnagent.PathSync, resp.Credential, vpnagent.SyncRequest{Revision: 5, WaitSeconds: 10})
	var desired vpnagent.SyncResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &desired)
	if elapsed := time.Since(start); rec.Code != http.StatusOK || desired.Revision != 6 || elapsed < 150*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("long-poll: %d revision %d after %s", rec.Code, desired.Revision, elapsed)
	}

	// Up to date and nothing changes: answered when the wait ends.
	a.maxWait = 300 * time.Millisecond
	start = time.Now()
	rec = post(mux, vpnagent.PathSync, resp.Credential, vpnagent.SyncRequest{Revision: 6, WaitSeconds: 10})
	if rec.Code != http.StatusOK || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("timeout: %d after %s", rec.Code, time.Since(start))
	}
}
