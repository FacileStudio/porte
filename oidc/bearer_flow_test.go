package oidc

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

// accessToken mints what registre hands an app after a human signs in: an
// RS256 access token for this client, carrying the user's subject.
func (p *provider) accessToken() string {
	now := time.Now()
	return p.sign(map[string]any{
		"iss":   p.issuer(),
		"sub":   p.subject,
		"aud":   "test-client",
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"email": p.email,
	})
}

// whoami calls the harness's authenticated route carrying a bearer token.
func whoami(t *testing.T, h *harness, accessToken string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, h.app.URL+"/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := h.app.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

// TestARegistreTokenAuthenticatesThroughTheWholeKit is the end-to-end proof:
// a real oidc.New, its real JWKS verifier, a token the provider actually
// signed, carried on Authorization through the middleware to a handler. It is
// here rather than in oidc/jwt because the wiring is what is being asserted —
// that New hands the manager a verifier holding the identity store.
func TestARegistreTokenAuthenticatesThroughTheWholeKit(t *testing.T) {
	h := newHarness(t, func(cfg *porte.Config) { cfg.MachineAudience = "test-client" })
	saveIdentity(t, h.stores, h.idp.issuer(), h.idp.subject, 7)

	accessToken := h.idp.accessToken()

	response := whoami(t, h, accessToken)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("a live registre token answered %d, want 200", response.StatusCode)
	}
	var identity porte.Identity
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatalf("decoding the identity: %v", err)
	}
	if identity.UserID != 7 {
		t.Errorf("UserID = %d, want 7 — one login for the suite means the local account", identity.UserID)
	}

	h.stores.mu.Lock()
	delete(h.stores.identities, h.idp.issuer()+"\x00"+h.idp.subject)
	h.stores.mu.Unlock()

	after := whoami(t, h, accessToken)
	defer func() { _ = after.Body.Close() }()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a deactivated account answered %d, want 401", after.StatusCode)
	}
}
