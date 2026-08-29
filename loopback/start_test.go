package loopback_test

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/FacileStudio/porte/loopback"
)

// porte reads exactly these three parameters. A renamed one is not an error
// anywhere: the browser completes an ordinary web login and the listener waits
// out its three minutes for a redirect nobody sends.
func TestLoginURLCarriesTheParametersPorteReads(t *testing.T) {
	listener := listen(t)

	target, err := url.Parse(listener.LoginURL("https://courrier.facile.studio", "/api", "nonce-1"))
	if err != nil {
		t.Fatalf("LoginURL did not produce a URL: %v", err)
	}
	query := target.Query()
	if query.Get("flow") != "cli" {
		t.Errorf("flow = %q, want cli", query.Get("flow"))
	}
	if query.Get("port") != strconv.Itoa(listener.Port()) {
		t.Errorf("port = %q, want the bound port %d", query.Get("port"), listener.Port())
	}
	if query.Get("cli_state") != "nonce-1" {
		t.Errorf("cli_state = %q, want the nonce back", query.Get("cli_state"))
	}
}

// The mount point is the app's, not porte's. Hardcoding /api is what three CLIs
// did, and the first app to serve its API from somewhere else would have broken
// all three at once.
func TestLoginURLHonoursTheMountPoint(t *testing.T) {
	listener := listen(t)
	port := strconv.Itoa(listener.Port())

	cases := []struct {
		name   string
		origin string
		mount  string
		want   string
	}{
		{"the suite's mount", "https://courrier.facile.studio", "/api", "https://courrier.facile.studio/api/auth/oidc"},
		{"a trailing slash on the origin", "https://courrier.facile.studio/", "/api", "https://courrier.facile.studio/api/auth/oidc"},
		{"slashes are the caller's to forget", "https://app.test", "api/", "https://app.test/api/auth/oidc"},
		{"served from the root", "https://app.test", "", "https://app.test/auth/oidc"},
		{"a root spelled as a slash", "https://app.test", "/", "https://app.test/auth/oidc"},
		{"somewhere else entirely", "https://app.test", "/v2/backend", "https://app.test/v2/backend/auth/oidc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := listener.LoginURL(tc.origin, tc.mount, "n")
			want := tc.want + "?cli_state=n&flow=cli&port=" + port
			if got != want {
				t.Fatalf("LoginURL = %q, want %q", got, want)
			}
		})
	}
}

// porte bounds the nonce at 128 characters and refuses anything outside
// [A-Za-z0-9-_], so this is not a free choice: a nonce it will not echo is a
// login that fails before the browser leaves.
func TestRandomStateFitsPortesBoundAndAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		state, err := loopback.RandomState()
		if err != nil {
			t.Fatalf("RandomState: %v", err)
		}
		if seen[state] {
			t.Fatal("RandomState repeated itself, so it proves nothing about which login answered")
		}
		seen[state] = true
		if len(state) == 0 || len(state) > 128 {
			t.Fatalf("state is %d characters, outside porte's bound", len(state))
		}
		for _, r := range state {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				t.Fatalf("state %q carries %q, which needs escaping in a URL", state, r)
			}
		}
	}
}

func listen(t *testing.T) *loopback.Listener {
	t.Helper()
	listener, err := loopback.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
