package coreclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProjectExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/core/projects/p-1":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/core/projects/p-2":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	c := New(base, http.DefaultTransport)

	if ok, err := c.ProjectExists(context.Background(), "Bearer tok", "p-1"); !ok || err != nil {
		t.Errorf("p-1: %v %v", ok, err)
	}
	if ok, err := c.ProjectExists(context.Background(), "Bearer tok", "p-2"); ok || err != nil {
		t.Errorf("p-2: %v %v", ok, err)
	}
	if _, err := c.ProjectExists(context.Background(), "Bearer tok", "p-3"); err == nil {
		t.Error("a 500 must be an error")
	}
	if _, err := c.ProjectExists(context.Background(), "Bearer other", "p-1"); err == nil {
		t.Error("a 401 must be an error")
	}
}
