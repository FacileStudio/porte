package mcpauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/FacileStudio/porte/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

func TestMetadataURLInsertsTheWellKnownSuffix(t *testing.T) {
	cases := map[string]string{
		resource:                        metadataURL,
		"https://app.example/":          "https://app.example/.well-known/oauth-protected-resource",
		"https://app.example":           "https://app.example/.well-known/oauth-protected-resource",
		"http://127.0.0.1:8080/api/mcp": "http://127.0.0.1:8080/.well-known/oauth-protected-resource/api/mcp",
	}
	for in, want := range cases {
		if got, err := mcpauth.MetadataURL(in); err != nil || got != want {
			t.Errorf("MetadataURL(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	if _, err := mcpauth.MetadataURL("/mcp"); err == nil {
		t.Error("a relative resource was accepted")
	}
}

func TestProtectedResourceMetadataServesThroughTheSDK(t *testing.T) {
	scopes := mcpauth.ScopesFor("courrier").List()
	handler := auth.ProtectedResourceMetadataHandler(
		mcpauth.ProtectedResourceMetadata(resource, "https://registre.example", scopes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	var got oauthex.ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Resource != resource || !slices.Equal(got.AuthorizationServers, []string{"https://registre.example"}) ||
		!slices.Equal(got.ScopesSupported, []string{"courrier.read", "courrier.write"}) {
		t.Errorf("metadata = %+v", got)
	}
}
