package authz

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
)

func TestRoleModel(t *testing.T) {
	want := []string{"admin", "analyst", "lab-researcher", "operator", "owner", "viewer"}
	if got := Roles(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Roles() = %v, want %v", got, want)
	}

	// Every role may read; only owner and admin may change projects.
	writers := map[string]bool{"owner": true, "admin": true}
	for _, role := range Roles() {
		if !Allowed([]string{role}, CoreProjectsRead) {
			t.Errorf("%s cannot read projects", role)
		}
		for _, perm := range []string{CoreProjectsCreate, CoreProjectsDelete} {
			if got := Allowed([]string{role}, perm); got != writers[role] {
				t.Errorf("Allowed(%s, %s) = %v, want %v", role, perm, got, writers[role])
			}
		}
	}
}

func TestAllowedDeniesByDefault(t *testing.T) {
	if Allowed(nil, CoreProjectsRead) {
		t.Error("no roles must grant nothing")
	}
	if Allowed([]string{"superuser", "offline_access"}, CoreProjectsRead) {
		t.Error("unknown roles must grant nothing")
	}
	if Allowed([]string{"owner"}, "core.projects.undefined") {
		t.Error("undefined permission must be denied")
	}
}

func TestPermissionsForIsSortedUnion(t *testing.T) {
	got := PermissionsFor([]string{"viewer", "analyst", "unknown"})
	want := []string{"cloud.audit.read", "cloud.resources.read", "core.projects.read", "system.status.read"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PermissionsFor = %v, want %v", got, want)
	}
	if got := PermissionsFor(nil); len(got) != 0 {
		t.Errorf("PermissionsFor(nil) = %v", got)
	}
}

func TestRequire(t *testing.T) {
	h := httpx.Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), Require(CoreProjectsCreate))

	cases := []struct {
		name      string
		principal *authn.Principal
		want      int
	}{
		{"admin allowed", &authn.Principal{Subject: "a", Roles: []string{"admin"}}, http.StatusNoContent},
		{"viewer forbidden", &authn.Principal{Subject: "v", Roles: []string{"viewer"}}, http.StatusForbidden},
		{"no roles forbidden", &authn.Principal{Subject: "n"}, http.StatusForbidden},
		{"unauthenticated", nil, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.principal != nil {
				req = req.WithContext(authn.WithPrincipal(req.Context(), tc.principal))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestCloudRoleModel(t *testing.T) {
	cases := map[string][]string{
		CloudResourcesRead:   {"admin", "analyst", "lab-researcher", "operator", "owner", "viewer"},
		CloudWorkloadsManage: {"admin", "operator", "owner"},
		CloudNetworksManage:  {"admin", "operator", "owner"},
		CloudNodesManage:     {"admin", "owner"},
		CloudQuotasManage:    {"admin", "owner"},
		CloudAuditRead:       {"admin", "analyst", "owner"},
	}
	for perm, want := range cases {
		var got []string
		for _, role := range Roles() {
			if Allowed([]string{role}, perm) {
				got = append(got, role)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s granted to %v, want %v", perm, got, want)
		}
	}
}
