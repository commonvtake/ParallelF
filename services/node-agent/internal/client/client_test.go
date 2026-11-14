package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

func TestCredentialsFileIsPrivateAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "creds.json")
	if _, ok, err := LoadCredentials(path); ok || err != nil {
		t.Fatalf("missing file: %v %v", ok, err)
	}
	want := Credentials{NodeID: "n", Token: "t", Name: "host", CloudURL: "http://x"}
	if err := SaveCredentials(path, want); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	got, ok, err := LoadCredentials(path)
	if !ok || err != nil || got != want {
		t.Fatalf("got %+v %v %v", got, ok, err)
	}
}

func TestSyncSendsProtocolHeaderAndHandles401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(cloudagent.VersionHeader) != cloudagent.Version || r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(cloudagent.SyncResponse{NodeID: "n-1", SyncIntervalSeconds: 3})
	}))
	defer srv.Close()
	c := New(srv.URL)

	resp, err := c.Sync(context.Background(), "good", cloudagent.SyncRequest{})
	if err != nil || resp.NodeID != "n-1" {
		t.Fatalf("%+v %v", resp, err)
	}
	if _, err := c.Sync(context.Background(), "bad", cloudagent.SyncRequest{}); err != ErrUnauthorized {
		t.Fatalf("got %v", err)
	}
}
