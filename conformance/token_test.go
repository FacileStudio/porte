package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
	"github.com/FacileStudio/porte/session"
)

var tokenAlphabet = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func TestTokenVector(t *testing.T) {
	var cases []testCase
	for _, c := range [][2]string{
		{"empty", ""}, {"ascii", "abc"}, {"session shaped", "dGhpcyBpcyBhIHNlc3Npb24gdG9rZW4gZm9yIHRlc3Rz"}, {"utf8", "é"},
	} {
		name, token := c[0], c[1]
		cases = append(cases, testCase{
			Name:  "hash " + name,
			Input: map[string]string{"kind": "hash", "token": token},
			Want:  map[string]string{"hash": porte.HashToken(token)},
		})
	}
	minted := make([]string, 64)
	for i := range minted {
		token, err := porte.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if len(token) != 43 || !tokenAlphabet.MatchString(token) {
			t.Fatalf("NewToken returned %q, outside the pinned shape", token)
		}
		minted[i] = token
	}
	cases = append(cases, testCase{
		Name:  "new_token shape",
		Input: map[string]string{"kind": "new_token"},
		Want:  map[string]any{"token_length": 43, "decoded_bytes": 32, "alphabet": tokenAlphabet.String(), "padding": false},
	})
	cases = append(append(cases, browserTokenCase(t)), browserSessionCases(t)...)
	cases = append(cases, compareCases()...)
	pin(t, "token", nil, cases)
}

func browserTokenCase(t *testing.T) testCase {
	t.Helper()
	browser, err := porte.NewBrowserToken()
	if err != nil {
		t.Fatalf("NewBrowserToken: %v", err)
	}
	prefix := porte.BrowserTokenPrefix
	if len(browser) != 45 || browser[:len(prefix)] != prefix || !tokenAlphabet.MatchString(browser[len(prefix):]) {
		t.Fatalf("NewBrowserToken returned %q, outside the pinned shape", browser)
	}
	return testCase{
		Name:  "new_browser_token shape",
		Input: map[string]string{"kind": "new_browser_token"},
		Want:  map[string]any{"prefix": prefix, "token_length": 45, "decoded_bytes_after_prefix": 32, "alphabet_after_prefix": tokenAlphabet.String(), "padding": false},
	}
}

type browserInput struct {
	Kind      string `json:"kind"`
	Token     string `json:"token"`
	Transport string `json:"transport"`
	Label     string `json:"label"`
}

func browserSessionCases(t *testing.T) []testCase {
	t.Helper()
	plain := strings.Repeat("A", 41)
	inputs := map[string]browserInput{
		"plain token starting with b- is not a browser session": {Token: "b-" + plain, Transport: "cookie"},
		"browser token in the cookie is a browser session":      {Token: porte.BrowserTokenPrefix + plain + "AA", Transport: "cookie"},
		"browser token as a bearer is not a browser session":    {Token: porte.BrowserTokenPrefix + plain + "AA", Transport: "bearer"},
		"browser token on a labelled row is not a browser session": {
			Token: porte.BrowserTokenPrefix + plain + "AA", Transport: "cookie", Label: "ci",
		},
		"plain token in the cookie is not a browser session": {Token: plain + "AA", Transport: "cookie"},
	}
	cases := make([]testCase, 0, len(inputs))
	for _, name := range sortedKeys(inputs) {
		in := inputs[name]
		in.Kind = "browser_session"
		cases = append(cases, testCase{Name: name, Input: in, Want: map[string]bool{"browser_session": browserSessionOf(t, in)}})
	}
	return cases
}

func browserSessionOf(t *testing.T, in browserInput) bool {
	t.Helper()
	store := newSessions()
	manager, err := session.New(porte.Config{}, session.Deps{Sessions: store})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}
	row := porte.Session{UserID: 7, Label: in.Label, TokenHash: porte.HashToken(in.Token), ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := store.Create(context.Background(), row); err != nil {
		t.Fatalf("storing the session: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	if in.Transport == "cookie" {
		r.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: in.Token})
	} else {
		r.Header.Set("Authorization", "Bearer "+in.Token)
	}
	identity, err := manager.Authenticate(httptest.NewRecorder(), r)
	if err != nil {
		t.Fatalf("authenticating %q: %v", in.Token, err)
	}
	return identity.BrowserSession
}

func compareCases() []testCase {
	pairs := [][3]string{
		{"equal", "same", "same"}, {"case differs", "same", "Same"}, {"prefix", "short", "shorter"},
		{"both empty", "", ""}, {"one empty", "a", ""},
	}
	cases := make([]testCase, 0, len(pairs))
	for _, pair := range pairs {
		cases = append(cases, testCase{
			Name:  "compare " + pair[0],
			Input: map[string]string{"kind": "compare", "a": pair[1], "b": pair[2]},
			Want:  map[string]bool{"equal": porte.SecureCompare(pair[1], pair[2])},
		})
	}
	return cases
}

func TestSchemaVector(t *testing.T) {
	sum := sha256.Sum256([]byte(pg.Schema))
	tampered := pg.Schema[:len(pg.Schema)-1]
	tamperedSum := sha256.Sum256([]byte(tampered))
	pin(t, "schema", nil, []testCase{
		{Name: "pg.Schema", Input: map[string]string{}, Want: map[string]string{
			"sha256": hex.EncodeToString(sum[:]), "sql": pg.Schema,
		}},
		{Name: "one byte short does not match", Input: map[string]string{"sql": tampered}, Want: map[string]any{
			"sha256": hex.EncodeToString(tamperedSum[:]), "matches": false,
		}},
	})
}
