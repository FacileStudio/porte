package session

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestOnlyALoginSessionInTheCookieIsABrowserSession(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	login := issue(t, manager, 7)
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
		{"a login session in the cookie", cookieRequest(manager, login), true},
		{"the same login session as a bearer", bearer(login), false},
		{"a named API token as a bearer", bearer(named), false},
		{"a named API token sent as a cookie", cookieRequest(manager, named), false},
	}
	for _, c := range cases {
		if got := browserSessionOf(t, manager, c.r); got != c.want {
			t.Errorf("%s: BrowserSession = %v, want %v", c.name, got, c.want)
		}
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
