package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"flag"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/FacileStudio/porte"
	jwtpkg "github.com/FacileStudio/porte/oidc/jwt"
	"github.com/FacileStudio/tronc/errors"
)

const provisionVectorPath = "../conformance/vectors/provision_bearer.json"

var update = flag.Bool("update", false, "rewrite "+provisionVectorPath)

type provisionInput struct {
	Email          string   `json:"email"`
	EmailVerified  *bool    `json:"email_verified"`
	Roles          []string `json:"roles,omitempty"`
	RolesScope     bool     `json:"roles_scope,omitempty"`
	TrustUnclaimed bool     `json:"trust_email_without_verified_claim,omitempty"`
	Existing       bool     `json:"existing_account,omitempty"`
	Store          string   `json:"store,omitempty"`
	Ledger         string   `json:"erasures,omitempty"`
}

func provisionInputs() map[string]provisionInput {
	email, yes, no := "new@example.com", verified(true), verified(false)
	return map[string]provisionInput{
		"a verified email creates the account":      {Email: email, EmailVerified: yes},
		"an existing account is returned untouched": {Email: email, EmailVerified: yes, Existing: true},
		"no email": {EmailVerified: yes},
		"an email the provider says is unverified":     {Email: email, EmailVerified: no},
		"an email with no verified claim":              {Email: email},
		"no verified claim, trusted by configuration":  {Email: email, TrustUnclaimed: true},
		"an unverified email is never trusted":         {Email: email, EmailVerified: no, TrustUnclaimed: true},
		"a roles scope and no roles":                   {Email: email, EmailVerified: yes, RolesScope: true},
		"a roles scope and roles":                      {Email: email, EmailVerified: yes, RolesScope: true, Roles: []string{"admin"}},
		"the user store refuses the person":            {Email: email, EmailVerified: yes, Store: "refuses"},
		"the user store fails":                         {Email: email, EmailVerified: yes, Store: "fails"},
		"an erased subject":                            {Email: email, EmailVerified: yes, Ledger: "erased"},
		"the erasure ledger cannot be read":            {Email: email, EmailVerified: yes, Ledger: "fails"},
		"an erased subject that still has its account": {Email: email, EmailVerified: yes, Ledger: "erased", Existing: true},
	}
}

func provisionKit(t *testing.T, in provisionInput) (*harness, *countingUsers) {
	t.Helper()
	h, users := provisionHarness(t, func(cfg *porte.Config) {
		cfg.TrustEmailWithoutVerifiedClaim = in.TrustUnclaimed
		if in.RolesScope {
			cfg.ClaimsScope = "facile"
		}
	})
	switch in.Store {
	case "refuses":
		users.refuse = errors.Forbidden("this account is disabled")
	case "fails":
		users.refuse = errors.Internal("the database is down", nil)
	}
	l := &ledger{erased: map[string]bool{}, fail: in.Ledger == "fails"}
	if in.Ledger == "erased" {
		l.erase(h.idp.issuer(), "registre-sub")
	}
	h.kit.deps.Erased = l
	if in.Existing {
		existing := porte.StoredIdentity{UserID: 7, Provider: h.idp.issuer(), Subject: "registre-sub"}
		if err := (identityStore{h.stores}).Save(context.Background(), existing); err != nil {
			t.Fatal(err)
		}
	}
	return h, users
}

func provisionWant(t *testing.T, in provisionInput) map[string]any {
	t.Helper()
	h, users := provisionKit(t, in)
	claims := jwtpkg.Claims{Subject: "registre-sub", Email: in.Email, Roles: in.Roles}
	claims.Profile.EmailVerified = in.EmailVerified
	identity, err := h.kit.ProvisionBearer(context.Background(), claims)
	want := map[string]any{"upserts": users.calls.Load()}
	switch {
	case err == nil:
		want["outcome"], want["user_id_is_existing"] = "account", identity.UserID == 7
	case stderrors.Is(err, ErrProvisionRefused):
		want["outcome"], want["erased"] = "refused", stderrors.Is(err, porte.ErrSubjectErased)
	default:
		want["outcome"] = "failed"
	}
	return want
}

func TestProvisionBearerVector(t *testing.T) {
	inputs := provisionInputs()
	cases := []map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(inputs)) {
		cases = append(cases, map[string]any{"name": name, "input": inputs[name], "want": provisionWant(t, inputs[name])})
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"source": "github.com/FacileStudio/porte@v0.20.0", "subject": "provision_bearer",
		"fixtures": map[string]any{
			"subject":  "registre-sub, under the kit's issuer",
			"outcomes": "refused is a 401 invalid_token at mcpauth; failed is a 500; erased refusals are permission_denied wrapping ErrSubjectErased",
		},
		"cases": cases,
	}); err != nil {
		t.Fatal(err)
	}
	compareProvisionVector(t, buffer.Bytes())
}

func compareProvisionVector(t *testing.T, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(provisionVectorPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(provisionVectorPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s no longer matches what ProvisionBearer does; review, then run go test ./oidc -run ProvisionBearerVector -update", provisionVectorPath)
	}
}
