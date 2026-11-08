package mcpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacileStudio/porte/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearer struct{ token string }

func (b bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(req)
}

type whoami struct {
	UserID     int64 `json:"user_id"`
	ThirdParty bool  `json:"third_party"`
}

func TestAToolSeesTheResolvedAccountThroughAStatelessServer(t *testing.T) {
	r := newRegistre(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "courrier", Version: "test"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "courrier_whoami"},
		func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, whoami, error) {
			identity, _ := mcpauth.Identity(req.Extra.TokenInfo)
			return nil, whoami{UserID: identity.UserID, ThirdParty: mcpauth.ThirdParty(req.Extra.TokenInfo)}, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true})
	require := mcpauth.Require(newVerifier(t, r, identities{}), &auth.RequireBearerTokenOptions{Scopes: []string{"courrier.read"}})
	srv := httptest.NewServer(require(handler))
	t.Cleanup(srv.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer{bulleToken(t, r)}}, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "courrier_whoami"})
	if err != nil || result.IsError {
		t.Fatalf("call: %v, %+v", err, result)
	}
	got, _ := result.StructuredContent.(map[string]any)
	if got["user_id"] != float64(userID) || got["third_party"] != false {
		t.Errorf("structured content = %v", result.StructuredContent)
	}
}
