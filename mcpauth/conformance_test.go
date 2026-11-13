package mcpauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/FacileStudio/porte/mcpauth"
	"github.com/FacileStudio/porte/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const tokenVectorPath = "../conformance/vectors/mcpauth_tokens.json"

var update = flag.Bool("update", false, "rewrite "+tokenVectorPath)

type tokenInput struct {
	Claims    map[string]any `json:"claims"`
	Store     string         `json:"store,omitempty"`
	Provision string         `json:"provision,omitempty"`
}

func baseClaims(changes map[string]any) map[string]any {
	claims := map[string]any{
		"iss": "<issuer>", "sub": subject, "aud": resource, "client_id": "claude",
		"iat": 1600000000, "exp": 4102444800, "jti": "j1", "scope": "courrier.read",
	}
	maps.Copy(claims, changes)
	return claims
}

func newcomer() map[string]any {
	return baseClaims(map[string]any{"sub": "newcomer", "email": "new@example.com", "email_verified": true})
}

func tokenInputs() map[string]tokenInput {
	delegated := map[string]any{"aud": appAudience, "client_id": mcpauth.BulleClientID, "act": map[string]string{"sub": "bulle"}}
	return map[string]tokenInput{
		"a token for this resource":                  {Claims: baseClaims(nil)},
		"write implies read":                         {Claims: baseClaims(map[string]any{"scope": "courrier.write"})},
		"another resource":                           {Claims: baseClaims(map[string]any{"aud": "https://agenda.example/mcp"})},
		"the resource with a trailing slash":         {Claims: baseClaims(map[string]any{"aud": resource + "/"})},
		"the app audience without delegation":        {Claims: baseClaims(map[string]any{"aud": appAudience})},
		"the app audience on a delegated token":      {Claims: baseClaims(delegated)},
		"an audience list naming the resource":       {Claims: baseClaims(map[string]any{"aud": []string{"other", resource}})},
		"expired":                                    {Claims: baseClaims(map[string]any{"exp": 1600000000})},
		"no exp":                                     {Claims: baseClaims(map[string]any{"exp": nil})},
		"another issuer":                             {Claims: baseClaims(map[string]any{"iss": "https://elsewhere.example"})},
		"no subject":                                 {Claims: baseClaims(map[string]any{"sub": nil})},
		"a subject with no account":                  {Claims: baseClaims(map[string]any{"sub": "stranger"})},
		"the identity store fails":                   {Claims: baseClaims(nil), Store: "fails"},
		"a newcomer is provisioned":                  {Claims: newcomer(), Provision: "ok"},
		"a newcomer the provisioner refuses":         {Claims: newcomer(), Provision: "refused"},
		"a newcomer whose provisioning store fails":  {Claims: newcomer(), Provision: "fails"},
		"a known subject is never provisioned again": {Claims: baseClaims(nil), Provision: "ok"},
	}
}

func tokenVerifier(t *testing.T, r *registre, in tokenInput) (auth.TokenVerifier, *provisioner) {
	t.Helper()
	store := identities{}
	if in.Store == "fails" {
		store.fail = errStore
	}
	cfg := mcpauth.Config{
		Issuer: r.srv.URL, Resource: resource, ScopePrefix: "courrier", Audience: appAudience,
		Identities: store, Logger: slog.New(slog.DiscardHandler),
	}
	accounts := &provisioner{issuer: r.srv.URL}
	switch in.Provision {
	case "refused":
		accounts.answer = fmt.Errorf("%w: disabled", oidc.ErrProvisionRefused)
	case "fails":
		accounts.answer = errStore
	}
	if in.Provision != "" {
		cfg.Provision, cfg.Accounts = true, accounts
	}
	verifier, err := mcpauth.Verifier(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, accounts
}

func tokenWant(t *testing.T, r *registre, in tokenInput) map[string]any {
	t.Helper()
	claims := maps.Clone(in.Claims)
	if claims["iss"] == "<issuer>" {
		claims["iss"] = r.srv.URL
	}
	verify, accounts := tokenVerifier(t, r, in)
	info, err := verify(context.Background(), r.mint(t, claims), nil)
	switch {
	case errors.Is(err, auth.ErrInvalidToken):
		return map[string]any{"outcome": "invalid_token", "message": err.Error(), "provisionings": accounts.calls}
	case err != nil:
		return map[string]any{"outcome": "unavailable", "provisionings": accounts.calls}
	}
	identity, _ := mcpauth.Identity(info)
	return map[string]any{
		"outcome": "account", "user_id": info.UserID, "scopes": info.Scopes,
		"subject": identity.Subject, "actor": identity.Actor, "provisionings": accounts.calls,
	}
}

func TestMCPAuthTokenVector(t *testing.T) {
	r := newRegistre(t)
	inputs := tokenInputs()
	cases := []map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(inputs)) {
		cases = append(cases, map[string]any{"name": name, "input": inputs[name], "want": tokenWant(t, r, inputs[name])})
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"source": "github.com/FacileStudio/porte/mcpauth@v0.3.0", "subject": "mcpauth_tokens",
		"fixtures": map[string]any{
			"issuer": "<issuer> is Config.Issuer", "resource": resource, "audience": appAudience,
			"scope_prefix": "courrier", "known_subject": subject, "known_user_id": userID,
			"provisioned_user_id": 77, "signing": "RS256, kid k1, typ at+jwt, the key the issuer's JWKS serves",
		},
		"cases": cases,
	}); err != nil {
		t.Fatal(err)
	}
	compareTokenVector(t, buffer.Bytes())
}

func compareTokenVector(t *testing.T, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(tokenVectorPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(tokenVectorPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s no longer matches what mcpauth does; review, then run go test -run MCPAuthTokenVector -update", tokenVectorPath)
	}
}
