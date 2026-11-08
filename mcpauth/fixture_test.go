package mcpauth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	resource    = "https://courrier.example/mcp"
	appAudience = "courrier-client"
	userID      = 42
	subject     = "user-sub"
)

type registre struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newRegistre(t *testing.T) *registre {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r := &registre{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": r.srv.URL, "jwks_uri": r.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{publicJWK(&key.PublicKey)}})
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func publicJWK(key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": "k1",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func (r *registre) mint(t *testing.T, overrides map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": r.srv.URL, "sub": subject, "aud": resource, "client_id": "claude",
		"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(),
		"jti": "j1", "scope": "courrier.read",
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)
			continue
		}
		claims[name] = value
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "at+jwt", "kid": "k1"})
	body, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func bulleToken(t *testing.T, r *registre) string {
	return r.mint(t, map[string]any{
		"aud": appAudience, "client_id": mcpauth.BulleClientID,
		"act": map[string]string{"sub": mcpauth.BulleClientID}, "scope": "courrier.read courrier.write",
	})
}

type identities struct {
	porte.IdentityStore
	fail error
}

func (s identities) Find(_ context.Context, provider, sub string) (porte.StoredIdentity, error) {
	if s.fail != nil {
		return porte.StoredIdentity{}, s.fail
	}
	if sub != subject {
		return porte.StoredIdentity{}, porte.ErrNotFound
	}
	return porte.StoredIdentity{UserID: userID, Provider: provider, Subject: sub}, nil
}

func newVerifier(t *testing.T, r *registre, store porte.IdentityStore) auth.TokenVerifier {
	t.Helper()
	verifier, err := mcpauth.Verifier(context.Background(), mcpauth.Config{
		Issuer: r.srv.URL, Resource: resource, ScopePrefix: "courrier", Audience: appAudience, Identities: store,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

var errStore = errors.New("database is down")
