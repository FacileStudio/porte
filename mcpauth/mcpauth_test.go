package mcpauth_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/FacileStudio/porte/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestAResourceBoundTokenYieldsTheLocalAccount(t *testing.T) {
	r := newRegistre(t)
	info, err := newVerifier(t, r, identities{})(context.Background(), r.mint(t, nil), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if info.UserID != "42" || !slices.Equal(info.Scopes, []string{"courrier.read"}) {
		t.Errorf("UserID = %q, Scopes = %v", info.UserID, info.Scopes)
	}
	if info.Expiration.Before(time.Now()) || info.Extra[mcpauth.ExtraClientID] != "claude" {
		t.Errorf("Expiration = %v, Extra = %v", info.Expiration, info.Extra)
	}
	if !mcpauth.ThirdParty(info) {
		t.Error("a token issued to claude is not third party")
	}
	identity, ok := mcpauth.Identity(info)
	if !ok || identity.UserID != userID || identity.Subject != subject {
		t.Errorf("Identity = %+v, %v", identity, ok)
	}
}

func TestABulleExchangedTokenIsAcceptedAndFirstParty(t *testing.T) {
	r := newRegistre(t)
	info, err := newVerifier(t, r, identities{})(context.Background(), bulleToken(t, r), nil)
	if err != nil {
		t.Fatalf("a Bulle exchanged token was refused: %v", err)
	}
	if mcpauth.ThirdParty(info) || info.Extra[mcpauth.ExtraActor] != "bulle" {
		t.Errorf("ThirdParty = true or actor missing: %v", info.Extra)
	}
	if !mcpauth.HasScope(info, "courrier.write") {
		t.Errorf("Scopes = %v", info.Scopes)
	}
}

func TestRefusedTokensAreInvalid(t *testing.T) {
	r := newRegistre(t)
	verify := newVerifier(t, r, identities{})
	cases := map[string]map[string]any{
		"wrong aud":                   {"aud": "https://agenda.example/mcp"},
		"app aud without delegation":  {"aud": appAudience},
		"expired":                     {"exp": time.Now().Add(-time.Hour).Unix()},
		"no exp":                      {"exp": nil},
		"wrong issuer":                {"iss": "https://elsewhere.example"},
		"subject without an account":  {"sub": "stranger"},
		"no subject":                  {"sub": nil},
		"aud is resource with suffix": {"aud": resource + "/"},
	}
	for name, overrides := range cases {
		_, err := verify(context.Background(), r.mint(t, overrides), nil)
		if !errors.Is(err, auth.ErrInvalidToken) || err.Error() != "invalid token" {
			t.Errorf("%s: err = %v, want the fixed invalid token error", name, err)
		}
	}
}

func TestAStoreFailureIsNotAnInvalidToken(t *testing.T) {
	r := newRegistre(t)
	_, err := newVerifier(t, r, identities{fail: errStore})(context.Background(), r.mint(t, nil), nil)
	if err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want an internal error so the client is not told to sign in again", err)
	}
}

func TestWriteImpliesRead(t *testing.T) {
	r := newRegistre(t)
	info, err := newVerifier(t, r, identities{})(context.Background(), r.mint(t, map[string]any{"scope": "courrier.write"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !mcpauth.HasScope(info, "courrier.read") {
		t.Errorf("Scopes = %v, want read implied by write", info.Scopes)
	}
}

func TestConfigIsValidated(t *testing.T) {
	r := newRegistre(t)
	bad := []mcpauth.Config{
		{Issuer: r.srv.URL, Resource: resource, ScopePrefix: "courrier"},
		{Issuer: r.srv.URL, Resource: "/mcp", ScopePrefix: "courrier", Identities: identities{}},
		{Issuer: r.srv.URL, Resource: resource + "#x", ScopePrefix: "courrier", Identities: identities{}},
		{Issuer: r.srv.URL, Resource: resource, ScopePrefix: "Courrier.read", Identities: identities{}},
	}
	for _, cfg := range bad {
		if _, err := mcpauth.Verifier(context.Background(), cfg); err == nil {
			t.Errorf("config %+v was accepted", cfg)
		}
	}
}
