package mcpauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/keys"
	"github.com/FacileStudio/porte/mcpauth"
	"github.com/FacileStudio/porte/session"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

type sessions struct{ rows map[string]porte.Session }

func (s *sessions) Create(_ context.Context, row porte.Session) (porte.Session, error) {
	row.ID = int64(len(s.rows) + 1)
	s.rows[row.TokenHash] = row
	return row, nil
}

func (s *sessions) Find(_ context.Context, hash string) (porte.Session, error) {
	if row, ok := s.rows[hash]; ok {
		return row, nil
	}
	return porte.Session{}, porte.ErrNotFound
}

func (s *sessions) Touch(context.Context, string, time.Time) error            { return nil }
func (s *sessions) Delete(context.Context, string) error                      { return nil }
func (s *sessions) DeleteByUser(context.Context, int64) (int64, error)        { return 0, nil }
func (s *sessions) DeleteLogins(context.Context, int64, int64) (int64, error) { return 0, nil }
func (s *sessions) ListByUser(context.Context, int64) ([]porte.Session, error) {
	return nil, nil
}
func (s *sessions) DeleteByID(context.Context, int64, int64) error          { return nil }
func (s *sessions) DeleteExpired(context.Context, time.Time) (int64, error) { return 0, nil }

type confirmPage struct {
	manager *session.Manager
	login   string
	cli     string
	named   string
}

func newConfirmPage(t *testing.T) confirmPage {
	t.Helper()
	manager, err := session.New(porte.Config{SuccessURL: "http://app.test/"}, session.Deps{
		Sessions: &sessions{rows: map[string]porte.Session{}},
	})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	login, _, err := manager.IssueCookieFor(context.Background(), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), porte.Session{UserID: 7})
	if err != nil {
		t.Fatalf("issuing a browser login: %v", err)
	}
	cli, _, err := manager.Issue(context.Background(), 7, "")
	if err != nil {
		t.Fatalf("issuing a CLI session: %v", err)
	}
	named, _, err := manager.Issue(context.Background(), 7, "agent")
	if err != nil {
		t.Fatalf("issuing a named token: %v", err)
	}
	return confirmPage{manager: manager, login: login, cli: cli, named: named}
}

func (p confirmPage) confirm(r *http.Request) (int, porte.Identity) {
	var got porte.Identity
	recorder := httptest.NewRecorder()
	p.manager.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := mcpauth.RequireOwnSession(r)
		if err != nil {
			w.WriteHeader(statusOf(err))
			return
		}
		got = identity
	})).ServeHTTP(recorder, r)
	return recorder.Code, got
}

func statusOf(err error) int {
	if errors.Is(err, mcpauth.ErrNotOwnSession) {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

func confirmRequest(cookie, authorization string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://app.test/api/mcp/pending/1/confirm", nil)
	r.Header.Set(porte.CSRFHeaderName, "1")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: cookie})
	}
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

func TestOnlyThePersonsBrowserSessionMayConfirm(t *testing.T) {
	page := newConfirmPage(t)
	status, identity := page.confirm(confirmRequest(page.login, ""))
	if status != http.StatusOK || identity.UserID != 7 {
		t.Fatalf("a browser session: status %d, user %d; want 200 and user 7", status, identity.UserID)
	}
	refused := map[string]*http.Request{
		"the login session as a bearer":            confirmRequest("", "Bearer "+page.login),
		"a named API token as a bearer":            confirmRequest("", "Bearer "+page.named),
		"a named API token sent as a cookie":       confirmRequest(page.named, ""),
		"a CLI exchange token sent as a cookie":    confirmRequest(page.cli, ""),
		"a browser session with a bearer attached": confirmRequest(page.login, "Bearer "+page.named),
	}
	for name, r := range refused {
		if status, _ := page.confirm(r); status != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, status)
		}
	}
}

func TestACookieFromBeforeTheBrowserPrefixStillSignsInButCannotConfirm(t *testing.T) {
	page := newConfirmPage(t)
	r := confirmRequest(page.cli, "")
	r.Method = http.MethodGet
	recorder := httptest.NewRecorder()
	var signedIn bool
	page.manager.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		signedIn = true
	})).ServeHTTP(recorder, r)
	if !signedIn {
		t.Fatalf("an unprefixed cookie session was signed out: status %d", recorder.Code)
	}
	if status, _ := page.confirm(confirmRequest(page.cli, "")); status != http.StatusForbidden {
		t.Fatalf("an unprefixed cookie session confirmed: status %d, want 403", status)
	}
}

func ownSessionOf(identity porte.Identity, ctx func(context.Context) context.Context) error {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(ctx(porte.WithIdentity(r.Context(), identity)))
	_, err := mcpauth.RequireOwnSession(r)
	return err
}

func TestEveryOtherCallerIsTheSameRefusal(t *testing.T) {
	same := func(ctx context.Context) context.Context { return ctx }
	browser := porte.Identity{UserID: 7, SessionID: 3, BrowserSession: true}
	if err := ownSessionOf(browser, same); err != nil {
		t.Fatalf("a browser session was refused: %v", err)
	}
	withKey := func(ctx context.Context) context.Context { return keys.With(ctx, keys.Key{ID: 1}) }
	cases := map[string]struct {
		identity porte.Identity
		ctx      func(context.Context) context.Context
	}{
		"a delegated JWT":              {porte.Identity{UserID: 7, Subject: "s", Actor: "bulle", Scopes: []string{"a.write"}}, same},
		"a machine token":              {porte.Identity{Subject: "suite-ci", Scopes: []string{"a.read"}}, same},
		"an MCP token":                 {porte.Identity{UserID: 7, Subject: "s"}, same},
		"an opaque bearer session":     {porte.Identity{UserID: 7, SessionID: 3}, same},
		"an actor on a session":        {porte.Identity{UserID: 7, SessionID: 3, BrowserSession: true, Actor: "agent"}, same},
		"a subject on a session":       {porte.Identity{UserID: 7, SessionID: 3, BrowserSession: true, Subject: "s"}, same},
		"scopes on a session":          {porte.Identity{UserID: 7, SessionID: 3, BrowserSession: true, Scopes: []string{"a.write"}}, same},
		"no session row":               {porte.Identity{UserID: 7, BrowserSession: true}, same},
		"no user":                      {porte.Identity{SessionID: 3, BrowserSession: true}, same},
		"a porte/keys API key as well": {browser, withKey},
	}
	for name, c := range cases {
		if err := ownSessionOf(c.identity, c.ctx); !errors.Is(err, mcpauth.ErrNotOwnSession) {
			t.Errorf("%s: err = %v, want ErrNotOwnSession", name, err)
		}
	}
}

func TestARequestWithoutAnIdentityIsUnauthenticated(t *testing.T) {
	_, err := mcpauth.RequireOwnSession(httptest.NewRequest(http.MethodPost, "/", nil))
	if err == nil || errors.Is(err, mcpauth.ErrNotOwnSession) {
		t.Fatalf("err = %v, want a 401", err)
	}
}

func TestAccountExistsReadsTheTokensAccount(t *testing.T) {
	gone := errors.New("no such user")
	lookup := func(_ context.Context, userID int64) (string, error) {
		if userID == 7 {
			return "seven", nil
		}
		return "", gone
	}
	info := func(userID string) *auth.TokenInfo { return &auth.TokenInfo{UserID: userID} }
	if account, err := mcpauth.AccountExists(context.Background(), info("7"), lookup); err != nil || account != "seven" {
		t.Fatalf("account = %q, err = %v; want seven", account, err)
	}
	refused := map[string]*auth.TokenInfo{"nil info": nil, "no user id": info(""), "not a number": info("x"), "a deleted account": info("8")}
	for name, in := range refused {
		if account, err := mcpauth.AccountExists(context.Background(), in, lookup); !errors.Is(err, mcpauth.ErrNoAccount) || account != "" {
			t.Errorf("%s: account = %q, err = %v; want ErrNoAccount", name, account, err)
		}
	}
	if _, err := mcpauth.AccountExists(context.Background(), info("8"), lookup); !errors.Is(err, gone) {
		t.Errorf("the lookup's error is not wrapped: %v", err)
	}
}
