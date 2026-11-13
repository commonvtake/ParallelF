package authn

import "github.com/commonvtake/parallelf/pkg/config"

// OIDCSettings identifies the identity provider that issues access tokens.
type OIDCSettings struct {
	// Issuer is the exact "iss" claim expected in tokens. It is the URL
	// browsers use to reach the provider.
	Issuer string
	// JWKSURL is where this service downloads the provider's signing keys.
	// Inside a container network it usually differs from Issuer's host.
	JWKSURL string
	// Audience must appear in the token's "aud" claim.
	Audience string
}

// LoadOIDCSettings reads PF_OIDC_ISSUER, PF_OIDC_JWKS_URL and
// PF_OIDC_AUDIENCE.
func LoadOIDCSettings(l *config.Loader) OIDCSettings {
	return OIDCSettings{
		Issuer:   l.URL("PF_OIDC_ISSUER").String(),
		JWKSURL:  l.URL("PF_OIDC_JWKS_URL").String(),
		Audience: l.String("PF_OIDC_AUDIENCE", "parallelf-api"),
	}
}
