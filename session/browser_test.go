package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

func browserSessionOf(t *testing.T, manager *Manager, r *http.Request) bool {
	t.Helper()
	identity, err := manager.Authenticate(httptest.NewRecorder(), r)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return identity.BrowserSession
}

func browserLogin(t *testing.T, manager *Manager, userID int64) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	token, _, err := manager.IssueCookieFor(context.Background(), httptest.NewRecorder(), r, porte.Session{UserID: userID})
	if err != nil {
		t.Fatalf("IssueCookieFor: %v", err)
	}
	return token
}

func TestOnlyABrowserLoginInTheCookieIsABrowserSession(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	browser := browserLogin(t, manager, 7)
	cli := issue(t, manager, 7)
	named, _, err := manager.Issue(context.Background(), 7, "ci")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	bearer := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"a browser login in the cookie", cookieRequest(manager, browser), true},
		{"the same browser login as a bearer", bearer(browser), false},
		{"a CLI exchange token sent as a cookie", cookieRequest(manager, cli), false},
		{"a CLI exchange token as a bearer", bearer(cli), false},
		{"a named API token as a bearer", bearer(named), false},
		{"a named API token sent as a cookie", cookieRequest(manager, named), false},
	}
	for _, c := range cases {
		if got := browserSessionOf(t, manager, c.r); got != c.want {
			t.Errorf("%s: BrowserSession = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOnlyIssueCookieForMintsABrowserToken(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	if browser := browserLogin(t, manager, 7); !strings.HasPrefix(browser, porte.BrowserTokenPrefix) {
		t.Fatalf("IssueCookieFor minted %q, want the %q prefix", browser, porte.BrowserTokenPrefix)
	}
	if cli := issue(t, manager, 7); strings.HasPrefix(cli, porte.BrowserTokenPrefix) {
		t.Fatalf("Issue minted %q with the browser prefix", cli)
	}
}

func TestAPrefixAddedToACLITokenIsNoSession(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	forged := porte.BrowserTokenPrefix + issue(t, manager, 7)
	if _, err := manager.Authenticate(httptest.NewRecorder(), cookieRequest(manager, forged)); err == nil {
		t.Fatalf("a CLI token behind the browser prefix authenticated")
	}
}

func plantPlain(t *testing.T, store *memory, token string) {
	t.Helper()
	if _, err := store.Create(context.Background(), porte.Session{UserID: 7, TokenHash: porte.HashToken(token), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestAPlainTokenStartingWithTheOldMarkIsNoBrowserSession(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	chance := "b-" + strings.Repeat("A", 41)
	plantPlain(t, store, chance)
	if browserSessionOf(t, manager, cookieRequest(manager, chance)) {
		t.Fatalf("a plain token starting with b- passed as a browser session")
	}
	if browser := browserLogin(t, manager, 7); !browserSessionOf(t, manager, cookieRequest(manager, browser)) {
		t.Fatalf("a %q browser login in the cookie was not a browser session", porte.BrowserTokenPrefix)
	}
}

func TestAPlainMintNeverCarriesTheBrowserPrefix(t *testing.T) {
	draws := []string{porte.BrowserTokenPrefix + "first", porte.BrowserTokenPrefix + "second", "plain"}
	mint := plainToken(func() (string, error) {
		token := draws[0]
		draws = draws[1:]
		return token, nil
	})
	if token, err := mint(); err != nil || token != "plain" {
		t.Fatalf("plainToken returned %q, %v; want the first draw without the browser prefix", token, err)
	}
}

func TestABearerJWTIsNeverABrowserSession(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	manager.WithJWT(&stubJWT{accepted: map[string]porte.Identity{
		"aaa.bbb.ccc": {UserID: 7, Subject: "subject-7", SessionID: 3, BrowserSession: true},
	}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
	if browserSessionOf(t, manager, r) {
		t.Fatalf("a bearer JWT passed as a browser session")
	}
}

func TestABrowserTokenSurvivesTheSetCookieRoundTrip(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	recorder := httptest.NewRecorder()
	token, _, err := manager.IssueCookieFor(context.Background(), recorder, httptest.NewRequest(http.MethodGet, "/", nil), porte.Session{UserID: 7})
	if err != nil {
		t.Fatalf("IssueCookieFor: %v", err)
	}
	header := recorder.Result().Header.Get("Set-Cookie")
	if !strings.Contains(header, "="+token+";") {
		t.Fatalf("Set-Cookie %q does not carry the token %q verbatim", header, token)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", strings.SplitN(header, ";", 2)[0])
	if !browserSessionOf(t, manager, r) {
		t.Fatalf("the browser cookie read back from Set-Cookie was not a browser session")
	}
}
