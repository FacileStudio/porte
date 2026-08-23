package oidc

import (
	"context"
	"os"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"
)

// TestNewBootsAgainstRegistre is the contract check between porte and
// registre: the deployed provider's discovery document has to be acceptable
// to the one client in the suite that reads it, go-oidc as wired inside New.
// Nothing outside registre had ever consumed what it serves before this ran.
//
// Skipped unless REGISTRE_ISSUER_URL points at a running registre, e.g.
//
//	REGISTRE_ISSUER_URL=https://sso.facile.studio go test ./oidc -run Registre -v
func TestNewBootsAgainstRegistre(t *testing.T) {
	issuer := os.Getenv("REGISTRE_ISSUER_URL")
	if issuer == "" {
		t.Skip("REGISTRE_ISSUER_URL unset; point it at a running registre")
	}

	stores := newFlowStores()
	cfg := porte.Config{
		Issuer:       issuer,
		ClientID:     "discovery-probe",
		ClientSecret: "unused-discovery-does-not-authenticate",
		RedirectURL:  "https://app.test/auth/oidc/callback",
		SuccessURL:   "https://app.test/",
	}
	manager, err := session.New(cfg, session.Deps{Sessions: stores.memory})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	kit, err := New(context.Background(), cfg, Deps{
		Users:      stores,
		Identities: identityStore{stores},
		Sessions:   manager,
		Codes:      codes{stores.memory},
	})
	if err != nil {
		t.Fatalf("New against %s: %v", issuer, err)
	}
	if !kit.Enabled() {
		t.Fatal("kit reports disabled after successful discovery")
	}

	var discovery struct {
		JwksURI       string `json:"jwks_uri"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := kit.provider.Claims(&discovery); err != nil {
		t.Fatalf("cannot read the discovery document back: %v", err)
	}
	if discovery.JwksURI == "" {
		t.Error("discovery carries no jwks_uri; no app could ever verify a registre token")
	}
}
