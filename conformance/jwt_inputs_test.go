package conformance

import (
	"strings"
	"testing"
)

type jwtInput struct {
	name  string
	token string
	extra []string
}

func jwtValidInputs(t *testing.T) []jwtInput {
	return []jwtInput{
		{name: "valid", token: sign(t, baseClaims())},
		{name: "audience as an array", token: sign(t, with(map[string]any{"aud": []string{"other", clientID}}))},
		{name: "an extra audience is accepted", extra: []string{"https://app.test/mcp"},
			token: sign(t, with(map[string]any{"aud": "https://app.test/mcp"}))},
		{name: "expired inside the leeway", token: sign(t, with(map[string]any{"exp": fixedNow - 29}))},
		{name: "nested act keeps the outer actor", token: sign(t, with(map[string]any{
			"act": map[string]any{"sub": "bulle", "act": map[string]any{"sub": "glouton"}},
		}))},
		{name: "act without a subject", token: sign(t, with(map[string]any{"act": map[string]any{}}))},
		{name: "scope splits on any whitespace", token: sign(t, with(map[string]any{"scope": " app.read  app.write\tx "}))},
		{name: "roles, client id and jti", token: sign(t, with(map[string]any{
			"roles": []string{"admin", "staff"}, "client_id": "bulle", "jti": "jti-1",
		}))},
		{name: "profile claims", token: sign(t, with(map[string]any{
			"email_verified": "true", "preferred_username": "user", "picture": "https://sso.test/a.png", "locale": "fr",
		}))},
		{name: "odd profile types drop the claim, not the token", token: sign(t, with(map[string]any{
			"email_verified": "yes", "locale": 5,
		}))},
		{name: "email_verified false", token: sign(t, with(map[string]any{"email_verified": false}))},
	}
}

func jwtInvalidInputs(t *testing.T) []jwtInput {
	valid := sign(t, baseClaims())
	parts := strings.Split(valid, ".")
	return []jwtInput{
		{name: "wrong audience", token: sign(t, with(map[string]any{"aud": "other-app"}))},
		{name: "no audience", token: sign(t, with(map[string]any{"aud": nil}))},
		{name: "expired past the leeway", token: sign(t, with(map[string]any{"exp": fixedNow - 31}))},
		{name: "no exp is expired", token: sign(t, with(map[string]any{"exp": nil}))},
		{name: "not valid yet", token: sign(t, with(map[string]any{"nbf": fixedNow + 31}))},
		{name: "issued in the future", token: sign(t, with(map[string]any{"iat": fixedNow + 31}))},
		{name: "wrong issuer", token: sign(t, with(map[string]any{"iss": "https://evil.test"}))},
		{name: "issuer with a trailing slash", token: sign(t, with(map[string]any{"iss": issuer + "/"}))},
		{name: "alg none", token: segment(t, map[string]any{"alg": "none"}) + "." + parts[1] + "."},
		{name: "alg HS256 keyed with the client id", token: hs256(t, baseClaims())},
		{name: "unknown kid", token: signWith(t, provider.key, map[string]any{"alg": "RS256", "kid": "other"}, baseClaims())},
		{name: "signed by another key under the right kid",
			token: signWith(t, provider.rogue, map[string]any{"alg": "RS256", "kid": keyID}, baseClaims())},
		{name: "payload swapped after signing", token: parts[0] + "." + segment(t, with(map[string]any{"sub": "admin"})) + "." + parts[2]},
		{name: "two segments", token: parts[0] + "." + parts[1]},
		{name: "payload is not JSON", token: signSegments(t, provider.key, parts[0], "bm90IGpzb24")},
	}
}

func jwtInputs(t *testing.T) []jwtInput {
	return append(jwtValidInputs(t), jwtInvalidInputs(t)...)
}
