package jwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type keyServer struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetches int
}

func newKeyServer(t *testing.T) (*keyServer, *httptest.Server) {
	t.Helper()
	server := &keyServer{keys: map[string]*rsa.PublicKey{}}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		server.mu.Lock()
		defer server.mu.Unlock()
		server.fetches++
		keys := []map[string]string{}
		for kid, key := range server.keys {
			keys = append(keys, map[string]string{
				"kty": "RSA",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(exponentBytes(key.E)),
			})
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return server, srv
}

func (s *keyServer) setKey(kid string, key *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[kid] = key
}

func (s *keyServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func exponentBytes(e int) []byte {
	out := []byte{}
	for e > 0 {
		out = append([]byte{byte(e)}, out...)
		e >>= 8
	}
	return out
}

func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sign(t *testing.T, key *rsa.PrivateKey, kid, alg string, payload map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) +
		"." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func token(t *testing.T, key *rsa.PrivateKey, issuer string, overrides map[string]any) string {
	payload := map[string]any{
		"iss": issuer,
		"aud": "registre",
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "machine:ci",
	}
	for claim, value := range overrides {
		payload[claim] = value
	}
	return sign(t, key, "kid-1", "RS256", payload)
}

func newVerifier(t *testing.T, issuer string) *Verifier {
	t.Helper()
	verifier, err := New(context.Background(), Config{Issuer: issuer, Audience: "registre"})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func TestAWellFormedTokenVerifies(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	got, err := newVerifier(t, srv.URL).Verify(context.Background(), token(t, key, srv.URL, nil))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "machine:ci" {
		t.Errorf("subject = %q", got.Subject)
	}
}

func TestAWrongAudienceIsRefused(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	_, err := newVerifier(t, srv.URL).Verify(context.Background(),
		token(t, key, srv.URL, map[string]any{"aud": "someone-else"}))
	if err == nil {
		t.Fatal("a token for another relying party verified")
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	expired := token(t, key, srv.URL, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	if _, err := newVerifier(t, srv.URL).Verify(context.Background(), expired); err == nil {
		t.Fatal("an expired token verified")
	}
}

func TestAWrongIssuerIsRefused(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	foreign := token(t, key, "https://evil.example", nil)
	if _, err := newVerifier(t, srv.URL).Verify(context.Background(), foreign); err == nil {
		t.Fatal("a token from another issuer verified")
	}
}

func TestANonRS256TokenIsRefused(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	confused := fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"kid-1"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+srv.URL+`","aud":"registre","exp":9999999999}`)),
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature")))
	if _, err := newVerifier(t, srv.URL).Verify(context.Background(), confused); err == nil {
		t.Fatal("an algorithm-confusion token verified")
	}
}

func TestAGarbageTokenIsRefused(t *testing.T) {
	_, srv := newKeyServer(t)
	verifier := newVerifier(t, srv.URL)
	for _, raw := range []string{"", "abc", "a.b.c.d", "not.a.token!"} {
		if _, err := verifier.Verify(context.Background(), raw); err == nil {
			t.Errorf("%q verified", raw)
		}
	}
}

func TestNewRefusesAMisconfiguredIssuer(t *testing.T) {
	if _, err := New(context.Background(), Config{Audience: "registre"}); err == nil {
		t.Error("no issuer accepted")
	}
	if _, err := New(context.Background(), Config{Issuer: "https://x.example"}); err == nil {
		t.Error("no audience accepted")
	}
	if _, err := New(context.Background(), Config{Issuer: strings.TrimSuffix("https://127.0.0.1:1", "/"), Audience: "registre"}); err == nil {
		t.Error("an unreachable issuer should fail at construction")
	}
}
