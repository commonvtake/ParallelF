// Package oidcverifier validates OIDC access tokens (JWTs) against an
// identity provider's JSON Web Key Set using github.com/coreos/go-oidc.
//
// It checks the signature, the pinned signing algorithm, issuer, audience
// and expiry. Realm roles are read from Keycloak's "realm_access.roles"
// claim.
package oidcverifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/commonvtake/parallelf/pkg/authn"
)

// Verifier implements authn.Verifier.
type Verifier struct {
	verifier *oidc.IDTokenVerifier
}

// New returns a Verifier. Signing keys are downloaded lazily from
// settings.JWKSURL and cached; ctx bounds the lifetime of those background
// fetches and should live as long as the process.
func New(ctx context.Context, settings authn.OIDCSettings) *Verifier {
	keySet := oidc.NewRemoteKeySet(ctx, settings.JWKSURL)
	return &Verifier{
		verifier: oidc.NewVerifier(settings.Issuer, keySet, &oidc.Config{
			ClientID:             settings.Audience,
			SupportedSigningAlgs: []string{oidc.RS256},
		}),
	}
}

type tokenClaims struct {
	Type              string `json:"typ"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// Verify validates rawToken and maps its claims to a Principal.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*authn.Principal, error) {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", authn.ErrInvalidToken, err.Error())
	}

	var claims tokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: unreadable claims: %s", authn.ErrInvalidToken, err.Error())
	}
	if token.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub claim", authn.ErrInvalidToken)
	}
	// Keycloak marks access tokens with typ=Bearer and ID tokens with typ=ID.
	// Only access tokens may be used to call APIs.
	if claims.Type != "" && !strings.EqualFold(claims.Type, "Bearer") {
		return nil, fmt.Errorf("%w: token type %q is not an access token", authn.ErrInvalidToken, claims.Type)
	}

	roles := claims.RealmAccess.Roles
	if roles == nil {
		roles = []string{}
	}
	username := claims.PreferredUsername
	if username == "" {
		username = token.Subject
	}
	return &authn.Principal{
		Subject:  token.Subject,
		Username: username,
		Email:    claims.Email,
		Name:     claims.Name,
		Roles:    roles,
	}, nil
}
