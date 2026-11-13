package conformance

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	issuer    = "https://sso.test"
	clientID  = "app-client"
	cliClient = "facile-cli"
	keyID     = "conformance-key"
)

type idp struct {
	key   *rsa.PrivateKey
	rogue *rsa.PrivateKey
}

var provider idp

// keysDown makes the fake issuer's JWKS unreachable ("unreachable") or answer
// a 500 ("error"); empty serves the keys.
var keysDown string

func TestMain(m *testing.M) {
	provider = idp{key: loadKey("testdata/idp_key.pem"), rogue: loadKey("testdata/rogue_key.pem")}
	http.DefaultTransport = provider
	os.Exit(m.Run())
}

func loadKey(path string) *rsa.PrivateKey {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		panic("no PEM block in " + path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return parsed.(*rsa.PrivateKey)
}

func (p idp) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != issuer {
		return nil, errors.New("conformance: no network outside the fake issuer")
	}
	recorder := httptest.NewRecorder()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(recorder, discovery())
	case "/keys":
		return p.keys(recorder)
	default:
		recorder.WriteHeader(http.StatusNotFound)
	}
	return recorder.Result(), nil
}

func (p idp) keys(recorder *httptest.ResponseRecorder) (*http.Response, error) {
	switch keysDown {
	case "unreachable":
		return nil, errors.New("conformance: the JWKS is unreachable")
	case "error":
		recorder.WriteHeader(http.StatusInternalServerError)
	default:
		writeJSON(recorder, p.jwks())
	}
	return recorder.Result(), nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func discovery() map[string]any {
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/keys",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
}

func (p idp) jwks() map[string]any {
	public := p.key.PublicKey
	return map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": keyID,
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}}
}

func segment(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding a token segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func signWith(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	return signSegments(t, key, segment(t, header), segment(t, claims))
}

func signSegments(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	signing := header + "." + payload
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing a token: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return signWith(t, provider.key, map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"}, claims)
}
