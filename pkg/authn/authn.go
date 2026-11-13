// Package authn authenticates API requests with OIDC access tokens.
//
// Services depend only on the Verifier interface. The production
// implementation lives in the oidcverifier subpackage and validates JWTs
// against the identity provider's published signing keys.
package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/logging"
)

// ErrInvalidToken is returned by a Verifier for any token that must be
// rejected. The wrapped cause is for logs only and never reaches clients.
var ErrInvalidToken = errors.New("invalid access token")

// Principal is the authenticated caller.
type Principal struct {
	Subject  string   `json:"subject"`
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Roles    []string `json:"roles"`
}

// Verifier validates a raw bearer token and returns its Principal.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Principal, error)
}

type principalKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated principal, if any.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}

// BearerToken extracts the token from an "Authorization: Bearer" header.
func BearerToken(r *http.Request) (string, bool) {
	const prefix = "bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	return token, token != ""
}

// Require returns middleware that rejects requests without a valid bearer
// token and stores the Principal in the request context.
func Require(v Verifier, logger *slog.Logger) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := BearerToken(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="parallelf"`)
				httpx.WriteProblem(w, r, httpx.Unauthorized("A bearer access token is required."))
				return
			}
			principal, err := v.Verify(r.Context(), token)
			if err != nil {
				logger.InfoContext(r.Context(), "access token rejected", slog.String("error", err.Error()))
				w.Header().Set("WWW-Authenticate", `Bearer realm="parallelf", error="invalid_token"`)
				httpx.WriteProblem(w, r, httpx.Unauthorized("The access token is invalid or expired."))
				return
			}
			ctx := WithPrincipal(r.Context(), principal)
			ctx = logging.With(ctx, slog.String("subject", principal.Subject))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
