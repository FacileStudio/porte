package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestAVerifierConsumesALiveRegistreToken is the consumer half of the
// machine-token contract: a real client_credentials token from the deployed
// registre verifies through this package — signature from its live JWKS, iss,
// aud and exp all checked. Registre's own suite proves the mint; this proves
// an app accepts it without any introspection round trip.
//
// Skipped unless all three variables are set:
//
//	REGISTRE_ROUNDTRIP_ISSUER=https://sso.facile.studio \
//	REGISTRE_ROUNDTRIP_CLIENT_ID=suite-ci \
//	REGISTRE_ROUNDTRIP_CLIENT_SECRET=... go test ./oidc/jwt -run Live -v
func TestAVerifierConsumesALiveRegistreToken(t *testing.T) {
	issuer := os.Getenv("REGISTRE_ROUNDTRIP_ISSUER")
	clientID := os.Getenv("REGISTRE_ROUNDTRIP_CLIENT_ID")
	clientSecret := os.Getenv("REGISTRE_ROUNDTRIP_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		t.Skip("REGISTRE_ROUNDTRIP_ISSUER, _CLIENT_ID and _CLIENT_SECRET unset; " +
			"the live verification needs real service-account credentials")
	}

	discovery, err := fetchDiscoveryDoc(issuer)
	if err != nil {
		t.Fatalf("fetching discovery from %s: %v", issuer, err)
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	response, err := http.PostForm(discovery.TokenEndpoint, form)
	if err != nil {
		t.Fatalf("requesting a token: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint = %d", response.StatusCode)
	}
	var granted struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&granted); err != nil {
		t.Fatalf("decoding the grant: %v", err)
	}

	verifier, err := New(context.Background(), Config{Issuer: issuer, Audience: "courrier"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims, err := verifier.Verify(context.Background(), granted.AccessToken)
	if err != nil {
		t.Fatalf("Verify refused a freshly minted token: %v", err)
	}
	if claims.Subject == "" {
		t.Error("identity carries no subject")
	}
	if _, err := verifier.Verify(context.Background(), granted.AccessToken+".tampered"); err == nil {
		t.Error("a tampered token verified")
	}
}

// discoveryDoc is the slice of the discovery document the live test needs.
type discoveryDoc struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func fetchDiscoveryDoc(issuer string) (discoveryDoc, error) {
	response, err := http.Get(strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return discoveryDoc{}, err
	}
	defer func() { _ = response.Body.Close() }()
	var doc discoveryDoc
	err = json.NewDecoder(response.Body).Decode(&doc)
	return doc, err
}
