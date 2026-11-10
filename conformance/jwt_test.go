package conformance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte/oidc/jwt"
)

const fixedNow = 1794312000

var reasons = [][2]string{
	{"not three segments", "malformed"},
	{"undecodable", "malformed"},
	{"unparsable", "malformed"},
	{"signing algorithm", "algorithm"},
	{"no key for kid", "unknown_key"},
	{"bad signature", "signature"},
	{"issuer", "issuer"},
	{"audience", "audience"},
	{"token expired", "expired"},
	{"not valid yet", "not_yet_valid"},
	{"issued in the future", "issued_in_future"},
}

func reason(err error) any {
	if err == nil {
		return nil
	}
	for _, known := range reasons {
		if strings.Contains(err.Error(), known[0]) {
			return known[1]
		}
	}
	return "unclassified: " + err.Error()
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss": issuer, "sub": userSubject, "aud": clientID,
		"exp": fixedNow + 3600, "iat": fixedNow - 60,
		"email": "user@example.test", "name": "Test User",
	}
}

func with(changes map[string]any) map[string]any {
	claims := baseClaims()
	for key, value := range changes {
		if value == nil {
			delete(claims, key)
			continue
		}
		claims[key] = value
	}
	return claims
}

func claimsView(c jwt.Claims) map[string]any {
	var verified any
	if c.Profile.EmailVerified != nil {
		verified = *c.Profile.EmailVerified
	}
	return map[string]any{
		"subject": c.Subject, "email": c.Email, "name": c.Name, "roles": orEmpty(c.Roles), "scopes": orEmpty(c.Scopes),
		"actor": c.Actor, "audience": orEmpty(c.Audience), "client_id": c.ClientID, "id": c.ID,
		"expires_at": c.ExpiresAt.Unix(),
		"profile": map[string]any{
			"email_verified": verified, "preferred_username": c.Profile.PreferredUsername,
			"picture": c.Profile.Picture, "locale": c.Profile.Locale,
		},
	}
}

func verify(t *testing.T, token string, extra []string) map[string]any {
	t.Helper()
	verifier, err := jwt.New(context.Background(), jwt.Config{
		Issuer: issuer, Audience: clientID, ExtraAudiences: extra,
		Now: func() time.Time { return time.Unix(fixedNow, 0) },
	})
	if err != nil {
		t.Fatalf("building the verifier: %v", err)
	}
	claims, err := verifier.Verify(context.Background(), token)
	want := map[string]any{"valid": err == nil, "reason": reason(err)}
	if err == nil {
		want["claims"] = claimsView(claims)
	}
	return want
}

func hs256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signing := segment(t, map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + segment(t, claims)
	mac := hmac.New(sha256.New, []byte(clientID))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestJWTVector(t *testing.T) {
	var cases []testCase
	for _, c := range jwtInputs(t) {
		cases = append(cases, testCase{
			Name:  c.name,
			Input: map[string]any{"token": c.token, "extra_audiences": c.extra},
			Want:  verify(t, c.token, c.extra),
		})
	}
	requireFailing(t, cases, func(c testCase) bool { return c.Want.(map[string]any)["valid"] == false })
	pin(t, "jwt", map[string]any{
		"issuer": issuer, "audience": clientID, "now": fixedNow, "leeway_seconds": 30,
		"discovery": discovery(), "jwks": provider.jwks(),
	}, cases)
}

func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
