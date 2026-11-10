package mcpauth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/FacileStudio/porte/mcpauth"
	"github.com/FacileStudio/porte/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func newcomerToken(t *testing.T, r *registre) string {
	return r.mint(t, map[string]any{
		"sub": "newcomer", "email": "new@example.com", "email_verified": true,
		"name": "New Person", "picture": "https://sso.example/p/1", "locale": "fr",
	})
}

func TestAFirstMCPCallProvisionsTheAccount(t *testing.T) {
	r := newRegistre(t)
	accounts := &provisioner{issuer: r.srv.URL}
	info, err := provisioningVerifier(t, r, accounts)(context.Background(), newcomerToken(t, r), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	identity, ok := mcpauth.Identity(info)
	if !ok || identity.UserID != 77 || accounts.calls != 1 {
		t.Fatalf("Identity = %+v, %v after %d provisionings", identity, ok, accounts.calls)
	}
	seen := accounts.seen
	if seen.Email != "new@example.com" || seen.Profile.EmailVerified == nil || !*seen.Profile.EmailVerified ||
		seen.Name != "New Person" || seen.Profile.Picture != "https://sso.example/p/1" || seen.Profile.Locale != "fr" {
		t.Fatalf("the provisioner saw %+v, want the token's profile", seen)
	}
}

func TestAnExistingAccountIsNeverProvisioned(t *testing.T) {
	r := newRegistre(t)
	accounts := &provisioner{issuer: r.srv.URL}
	info, err := provisioningVerifier(t, r, accounts)(context.Background(), r.mint(t, nil), nil)
	if err != nil || info.UserID != "42" || accounts.calls != 0 {
		t.Fatalf("info = %+v, %v after %d provisionings; want account 42 as is", info, err, accounts.calls)
	}
}

func TestARefusedProvisioningIsAnInvalidToken(t *testing.T) {
	r := newRegistre(t)
	accounts := &provisioner{issuer: r.srv.URL, answer: fmt.Errorf("%w: disabled", oidc.ErrProvisionRefused)}
	_, err := provisioningVerifier(t, r, accounts)(context.Background(), newcomerToken(t, r), nil)
	if !errors.Is(err, auth.ErrInvalidToken) || err.Error() != "invalid token" {
		t.Fatalf("err = %v, want the fixed invalid token error", err)
	}
	accounts.answer = errStore
	_, err = provisioningVerifier(t, r, accounts)(context.Background(), newcomerToken(t, r), nil)
	if err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want unavailability for a store that failed", err)
	}
}

func TestWithoutProvisionANewcomerIsRefused(t *testing.T) {
	r := newRegistre(t)
	_, err := newVerifier(t, r, identities{})(context.Background(), newcomerToken(t, r), nil)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want a refusal when the app did not opt in", err)
	}
}

func TestProvisionConfigIsValidated(t *testing.T) {
	r := newRegistre(t)
	base := mcpauth.Config{Issuer: r.srv.URL, Resource: resource, ScopePrefix: "courrier", Identities: identities{}}
	without, elsewhere := base, base
	without.Provision = true
	elsewhere.Provision, elsewhere.Accounts = true, &provisioner{issuer: "https://other.example"}
	for name, cfg := range map[string]mcpauth.Config{"no kit": without, "other issuer": elsewhere} {
		if _, err := mcpauth.Verifier(context.Background(), cfg); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}
