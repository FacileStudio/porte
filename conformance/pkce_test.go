package conformance

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"

	"golang.org/x/oauth2"
)

func challengeCases() []testCase {
	inputs := [][3]string{
		{"RFC 7636 appendix B", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", ""},
		{"43 characters, the shortest verifier", strings.Repeat("a", 43), ""},
		{"128 characters, the longest verifier", strings.Repeat("Z", 128), ""},
		{"unreserved punctuation", "abc-._~" + strings.Repeat("0", 40), ""},
		{"plain is not S256", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		{"a challenge for another verifier", strings.Repeat("a", 43), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
	}
	cases := make([]testCase, 0, len(inputs))
	for _, in := range inputs {
		challenge := oauth2.S256ChallengeFromVerifier(in[1])
		want := map[string]any{"challenge": challenge}
		input := map[string]string{"kind": "challenge", "verifier": in[1]}
		if in[2] != "" {
			input["offered_challenge"] = in[2]
			want["matches"] = in[2] == challenge
		}
		cases = append(cases, testCase{Name: in[0], Input: input, Want: want})
	}
	return cases
}

func authorizeCase(t *testing.T) testCase {
	t.Helper()
	response := newApp(t, oidcEnv(nil), nil).serve(httptest.NewRequest(http.MethodGet, "http://app.test"+porte.RouteLogin, nil))
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the authorize redirect: %v", err)
	}
	query := target.Query()
	for _, random := range []string{"state", "nonce", "code_challenge"} {
		if len(query.Get(random)) != 43 {
			t.Fatalf("%s = %q, want 43 base64url characters", random, query.Get(random))
		}
		query.Set(random, "<43 random base64url characters>")
	}
	target.RawQuery = ""
	params := map[string]string{}
	for key := range query {
		params[key] = query.Get(key)
	}
	return testCase{
		Name:  "the login redirect asks for S256",
		Input: map[string]any{"kind": "authorize", "path": porte.RouteLogin, "config": oidcEnv(nil)},
		Want:  map[string]any{"status": response.Code, "url": target.String(), "query": params},
	}
}

func TestPKCEVector(t *testing.T) {
	cases := append(challengeCases(), authorizeCase(t))
	if got := cases[0].Want.(map[string]any)["challenge"]; got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("the RFC 7636 appendix B verifier gives %v", got)
	}
	pin(t, "pkce", map[string]any{"method": "S256", "verifier_length": len(oauth2.GenerateVerifier())}, cases)
}
