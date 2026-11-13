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
