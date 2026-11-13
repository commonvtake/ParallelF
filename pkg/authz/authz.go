// Package authz maps platform roles to permissions.
//
// permissions.json is the single source of truth for the role model. Roles
// are issued by the identity provider as realm roles; permissions follow
// the pattern <domain>.<resource>.<verb>.
package authz

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
)

// Permissions used by Go services.
const (
	SystemStatusRead   = "system.status.read"
	CoreProjectsRead   = "core.projects.read"
	CoreProjectsCreate = "core.projects.create"
	CoreProjectsDelete = "core.projects.delete"
)

//go:embed permissions.json
var permissionsJSON []byte

var rolePermissions = mustLoad(permissionsJSON)

func mustLoad(raw []byte) map[string]map[string]struct{} {
	var doc struct {
		Roles map[string][]string `json:"roles"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(fmt.Sprintf("authz: invalid permissions.json: %v", err))
	}
	out := make(map[string]map[string]struct{}, len(doc.Roles))
	for role, perms := range doc.Roles {
		set := make(map[string]struct{}, len(perms))
		for _, p := range perms {
			set[p] = struct{}{}
		}
		out[role] = set
	}
	return out
}

// Roles returns every role defined in the role model, sorted.
func Roles() []string {
	roles := make([]string, 0, len(rolePermissions))
	for role := range rolePermissions {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}

// Allowed reports whether any of roles grants permission. Unknown roles
// grant nothing.
func Allowed(roles []string, permission string) bool {
	for _, role := range roles {
		if _, ok := rolePermissions[role][permission]; ok {
			return true
		}
	}
	return false
}

// PermissionsFor returns the sorted union of permissions granted by roles.
func PermissionsFor(roles []string) []string {
	set := make(map[string]struct{})
	for _, role := range roles {
		for p := range rolePermissions[role] {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Require returns middleware that rejects callers lacking permission. It
// must run after authn.Require.
func Require(permission string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := authn.PrincipalFrom(r.Context())
			if !ok {
				httpx.WriteProblem(w, r, httpx.Unauthorized("A bearer access token is required."))
				return
			}
			if !Allowed(principal.Roles, permission) {
				httpx.WriteProblem(w, r, httpx.Forbidden("Your role does not grant "+permission+"."))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
