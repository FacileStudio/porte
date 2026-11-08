package mcpauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacileStudio/porte/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const metadataURL = "https://courrier.example/.well-known/oauth-protected-resource/mcp"

func protected(t *testing.T, r *registre, scopes ...string) http.Handler {
	t.Helper()
	require := mcpauth.Require(newVerifier(t, r, identities{}), &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: metadataURL, Scopes: scopes,
	})
	return require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
}

func call(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func challenge(t *testing.T, rec *httptest.ResponseRecorder) oauthex.Challenge {
	t.Helper()
	challenges, err := oauthex.ParseWWWAuthenticate(rec.Header().Values("WWW-Authenticate"))
	if err != nil || len(challenges) != 1 {
		t.Fatalf("WWW-Authenticate %q: %v", rec.Header().Values("WWW-Authenticate"), err)
	}
	return challenges[0]
}

func TestMissingScopeIsAnInsufficientScopeChallenge(t *testing.T) {
	r := newRegistre(t)
	rec := call(protected(t, r, "courrier.write"), r.mint(t, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	got := challenge(t, rec)
	if got.Params["error"] != "insufficient_scope" || got.Params["scope"] != "courrier.write" ||
		got.Params["resource_metadata"] != metadataURL {
		t.Errorf("challenge = %+v", got)
	}
}

func TestAnInvalidTokenIsAnInvalidTokenChallenge(t *testing.T) {
	r := newRegistre(t)
	rec := call(protected(t, r, "courrier.read"), r.mint(t, map[string]any{"aud": "https://other.example/mcp"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := challenge(t, rec); got.Params["error"] != "invalid_token" || got.Params["resource_metadata"] != metadataURL {
		t.Errorf("challenge = %+v", got)
	}
}

func TestNoTokenIsAChallengeWithoutAnErrorCode(t *testing.T) {
	r := newRegistre(t)
	rec := call(protected(t, r, "courrier.read"), "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := challenge(t, rec); got.Params["error"] != "" || got.Params["resource_metadata"] != metadataURL {
		t.Errorf("challenge = %+v", got)
	}
}

func TestTheProtectedHandlerKeepsItsOwnResponse(t *testing.T) {
	r := newRegistre(t)
	rec := call(protected(t, r, "courrier.read"), r.mint(t, nil))
	if rec.Code != http.StatusForbidden || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("status = %d, WWW-Authenticate = %q: the handler's own 403 was rewritten",
			rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
