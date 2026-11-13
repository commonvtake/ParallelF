package oidcverifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/commonvtake/parallelf/pkg/authn"
)

const (
	testIssuer   = "http://localhost:8080/realms/parallelf"
	testAudience = "parallelf-api"
)

type fixture struct {
	key      *rsa.PrivateKey
	verifier *Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256), Use: "sig"},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &fixture{
		key: key,
		verifier: New(ctx, authn.OIDCSettings{
			Issuer:   testIssuer,
			JWKSURL:  srv.URL,
			Audience: testAudience,
		}),
	}
}

func validClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                testIssuer,
		"sub":                "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f",
		"aud":                []string{testAudience, "account"},
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"typ":                "Bearer",
		"preferred_username": "owner",
		"email":              "owner@parallelf.test",
		"name":               "Olivia Owner",
		"realm_access":       map[string]any{"roles": []string{"owner", "offline_access"}},
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyAcceptsValidAccessToken(t *testing.T) {
	f := newFixture(t)
	principal, err := f.verifier.Verify(context.Background(), signRS256(t, f.key, "key-1", validClaims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.Subject != "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f" || principal.Username != "owner" ||
		principal.Email != "owner@parallelf.test" || principal.Name != "Olivia Owner" {
		t.Errorf("unexpected principal: %+v", principal)
	}
	if len(principal.Roles) != 2 || principal.Roles[0] != "owner" {
		t.Errorf("roles = %v", principal.Roles)
	}
}

func TestVerifyRejectsInvalidTokens(t *testing.T) {
	f := newFixture(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(fn func(map[string]any)) string {
		claims := validClaims()
		fn(claims)
		return signRS256(t, f.key, "key-1", claims)
	}

	// Algorithm confusion: HMAC-sign with the RSA public key as the secret.
	publicDER, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hmacSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: publicDER},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	hs256Token, err := jwt.Signed(hmacSigner).Claims(validClaims()).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned token (alg=none).
	payload, err := json.Marshal(validClaims())
	if err != nil {
		t.Fatal(err)
	}
	noneToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."

	cases := map[string]string{
		"expired":               mutate(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"wrong issuer":          mutate(func(c map[string]any) { c["iss"] = "http://evil.example/realms/parallelf" }),
		"wrong audience":        mutate(func(c map[string]any) { c["aud"] = []string{"account"} }),
		"missing subject":       mutate(func(c map[string]any) { delete(c, "sub") }),
		"id token":              mutate(func(c map[string]any) { c["typ"] = "ID" }),
		"signed by other key":   signRS256(t, otherKey, "key-1", validClaims()),
		"unknown key id":        signRS256(t, otherKey, "key-2", validClaims()),
		"hs256 with public key": hs256Token,
		"alg none":              noneToken,
		"garbage":               "not-a-jwt",
		"empty":                 "",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			principal, err := f.verifier.Verify(context.Background(), token)
			if err == nil {
				t.Fatalf("Verify accepted the token, principal = %+v", principal)
			}
			if !errors.Is(err, authn.ErrInvalidToken) {
				t.Errorf("error %v does not wrap ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyDefaultsForMissingOptionalClaims(t *testing.T) {
	f := newFixture(t)
	claims := validClaims()
	delete(claims, "preferred_username")
	delete(claims, "realm_access")
	delete(claims, "typ")

	principal, err := f.verifier.Verify(context.Background(), signRS256(t, f.key, "key-1", claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.Username != principal.Subject {
		t.Errorf("username = %q, want fallback to subject", principal.Username)
	}
	if principal.Roles == nil || len(principal.Roles) != 0 {
		t.Errorf("roles = %#v, want empty non-nil slice", principal.Roles)
	}
}
