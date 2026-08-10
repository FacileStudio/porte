package session

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"

	"github.com/go-chi/chi/v5"
)

// memory is the session store in a map. It exists so the middleware can be
// tested without a database; the real one is in porte/pg and is tested against
// a real PostgreSQL.
type memory struct {
	mu       sync.Mutex
	sessions map[string]porte.Session
	nextID   int64
	touches  int
}

func newMemory() *memory { return &memory{sessions: map[string]porte.Session{}} }

func (m *memory) Create(_ context.Context, session porte.Session) (porte.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	session.ID = m.nextID
	m.sessions[session.TokenHash] = session
	return session, nil
}

func (m *memory) Find(_ context.Context, tokenHash string) (porte.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[tokenHash]
	if !ok {
		return porte.Session{}, porte.ErrNotFound
	}
	return session, nil
}

func (m *memory) Touch(_ context.Context, tokenHash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touches++
	session := m.sessions[tokenHash]
	session.LastUsedAt = at
	m.sessions[tokenHash] = session
	return nil
}

func (m *memory) Delete(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

func (m *memory) DeleteByUser(_ context.Context, userID int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	for hash, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, hash)
			deleted++
		}
	}
	return deleted, nil
}

func (m *memory) ListByUser(_ context.Context, userID int64) ([]porte.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var held []porte.Session
	for _, session := range m.sessions {
		if session.UserID == userID {
			held = append(held, session)
		}
	}
	return held, nil
}

func (m *memory) DeleteByID(_ context.Context, userID, sessionID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, session := range m.sessions {
		if session.ID == sessionID && session.UserID == userID {
			delete(m.sessions, hash)
			return nil
		}
	}
	return porte.ErrNotFound
}

func (m *memory) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	for hash, session := range m.sessions {
		// A nil expiry is a named API token. The real store spares them
		// and so does this one, or the test would prove nothing.
		if session.ExpiresAt.IsZero() || !session.ExpiresAt.Before(now) {
			continue
		}
		delete(m.sessions, hash)
		deleted++
	}
	return deleted, nil
}

func testManager(t *testing.T, store *memory, now time.Time) *Manager {
	t.Helper()
	manager, err := New(porte.Config{SuccessURL: "https://app.test/"}, Deps{
		Sessions: store,
		Logger:   slog.New(slog.DiscardHandler),
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return manager
}

// sessionCookie is the cookie a browser would actually send back to this
// manager: the __Host- prefixed name over https, the bare one otherwise.
func sessionCookie(manager *Manager, token string) *http.Cookie {
	name := porte.SessionCookieName
	if manager.cfg.HTTPS() {
		name = "__Host-" + name
	}
	return &http.Cookie{Name: name, Value: token}
}

// issue puts a live session in the store and returns its plaintext token.
func issue(t *testing.T, manager *Manager, userID int64) string {
	t.Helper()
	token, _, err := manager.Issue(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

func authenticated(manager *Manager) http.Handler {
	return manager.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := porte.From(r.Context())
		_ = json.NewEncoder(w).Encode(identity)
	}))
}

// cookieRequest is a browser GET carrying the session cookie, which is the
// transport the idle window applies to.
func cookieRequest(manager *Manager, token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(sessionCookie(manager, token))
	return request
}

func TestCookieTransportRequiresTheCSRFHeaderOnMutatingRequests(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)
	token := issue(t, manager, 7)

	cases := []struct {
		name   string
		method string
		header bool
		want   int
	}{
		{"a read is safe without it", http.MethodGet, false, http.StatusOK},
		{"a write without it is refused", http.MethodPost, false, http.StatusForbidden},
		{"a write with it is allowed", http.MethodPost, true, http.StatusOK},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(testCase.method, "/x", nil)
			request.AddCookie(sessionCookie(manager, token))
			if testCase.header {
				request.Header.Set(porte.CSRFHeaderName, "1")
			}
			recorder := httptest.NewRecorder()
			authenticated(manager).ServeHTTP(recorder, request)
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d, want %d (%s)", recorder.Code, testCase.want, recorder.Body)
			}
		})
	}
}

// A bearer caller is not a browser: nothing attaches the credential on its
// behalf, so there is no CSRF to defend against and demanding the header would
// break every CLI for nothing.
func TestBearerWritesDoNotNeedTheCSRFHeader(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)

	request := httptest.NewRequest(http.MethodPost, "/x", nil)
	request.Header.Set("Authorization", "Bearer "+issue(t, manager, 7))
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}
}

func TestNoCredentialIsReadFromTheQueryString(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)
	token := issue(t, manager, 7)

	for _, param := range []string{"token", "api_key", "access_token"} {
		request := httptest.NewRequest(http.MethodGet, "/x?"+param+"="+token, nil)
		recorder := httptest.NewRecorder()
		authenticated(manager).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("?%s= authenticated the request (status %d)", param, recorder.Code)
		}
	}
}

func TestExpiredSessionIsRefusedAndTheCookieCleared(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)
	token := issue(t, manager, 7)

	manager.now = func() time.Time { return now.Add(porte.DefaultSessionTTL + time.Second) }

	request := httptest.NewRequest(http.MethodGet, "/x", nil)
	request.AddCookie(sessionCookie(manager, token))
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if !strings.Contains(recorder.Header().Get("Set-Cookie"), porte.SessionCookieName+"=;") {
		t.Fatalf("the dead cookie was not cleared: %q", recorder.Header().Get("Set-Cookie"))
	}
}

// last_used_at is for recognising a session in a list, not for accounting. One
// UPDATE per request on the auth path of every call would be the most
// expensive column in the schema.
func TestSessionUseIsRecordedAtMostOncePerInterval(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)
	token := issue(t, manager, 7)

	send := func() {
		request := httptest.NewRequest(http.MethodGet, "/x", nil)
		request.AddCookie(sessionCookie(manager, token))
		authenticated(manager).ServeHTTP(httptest.NewRecorder(), request)
	}
	send()
	send()
	if store.touches != 0 {
		t.Fatalf("touched %d times inside the interval, want 0", store.touches)
	}

	manager.now = func() time.Time { return now.Add(touchInterval + time.Second) }
	send()
	if store.touches != 1 {
		t.Fatalf("touched %d times after the interval, want 1", store.touches)
	}
}

func TestTheSessionTokenIsNeverStoredInThePlain(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	token := issue(t, manager, 7)

	if _, ok := store.sessions[token]; ok {
		t.Fatal("the plaintext token is a key in the store")
	}
	if _, ok := store.sessions[porte.HashToken(token)]; !ok {
		t.Fatal("the session was not stored under its hash")
	}
}

// A thirty-day session that nothing can age out is the difference between a
// borrowed laptop being a bad afternoon and a bad month. The window is the one
// default porte does not inherit from the apps.
func TestASessionIdleForTooLongIsRefused(t *testing.T) {
	store := newMemory()
	issued := time.Now()
	manager := testManager(t, store, issued)
	token := issue(t, manager, 1)

	manager.now = func() time.Time { return issued.Add(porte.DefaultSessionIdleTTL + time.Minute) }
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, cookieRequest(manager, token))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an idle session authenticated: %d", recorder.Code)
	}

	// And the dead row is gone, so replaying the token costs nothing.
	if _, err := store.Find(context.Background(), porte.HashToken(token)); err == nil {
		t.Fatal("the idled-out session row survived")
	}
}

func TestASessionUsedInsideTheIdleWindowSurvives(t *testing.T) {
	issued := time.Now()
	manager := testManager(t, newMemory(), issued)
	token := issue(t, manager, 1)

	manager.now = func() time.Time { return issued.Add(porte.DefaultSessionIdleTTL - time.Hour) }
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, cookieRequest(manager, token))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a session used inside the window = %d, want 200", recorder.Code)
	}
}

func TestTheIdleWindowCanBeTurnedOff(t *testing.T) {
	issued := time.Now()
	store := newMemory()
	manager, err := New(porte.Config{SuccessURL: "https://app.test/", SessionIdleTTL: -1}, Deps{
		Sessions: store,
		Logger:   slog.New(slog.DiscardHandler),
		Now:      func() time.Time { return issued },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token := issue(t, manager, 1)

	// Well past the idle window, well inside the absolute one.
	manager.now = func() time.Time { return issued.Add(porte.DefaultSessionIdleTTL + 24*time.Hour) }
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, cookieRequest(manager, token))
	if recorder.Code != http.StatusOK {
		t.Fatalf("the idle window fired although it was disabled: %d", recorder.Code)
	}
}

// A CLI's token is a bearer, and a CLI nobody runs for a fortnight must not be
// silently signed out — it is the one credential with no human present to
// renew it. The idle window is for the browser transport.
func TestABearerIsNeverIdledOut(t *testing.T) {
	issued := time.Now()
	manager := testManager(t, newMemory(), issued)
	token := issue(t, manager, 1)

	manager.now = func() time.Time { return issued.Add(porte.DefaultSessionIdleTTL + 48*time.Hour) }
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a CLI bearer was idled out: %d", recorder.Code)
	}
}

// The whole point of the prefix is that a cookie which does not carry it is not
// trusted. A reader that falls back unconditionally accepts exactly the cookie
// a compromised sibling host plants, so the fallback is opt-in.
func TestAnUnprefixedCookieIsRefusedOverHTTPSByDefault(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	manager.cfg.RedirectURL = "https://app.test/auth/oidc/callback"
	token := issue(t, manager, 1)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: token})
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an unprefixed cookie authenticated over https: %d", recorder.Code)
	}

	// The prefixed one, same token, is accepted.
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.AddCookie(&http.Cookie{Name: "__Host-" + porte.SessionCookieName, Value: token})
	recorder = httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("the prefixed cookie was refused: %d", recorder.Code)
	}
}

// An app migrating off its own pre-porte cookie opts in for one SessionTTL.
func TestAcceptLegacyCookieReopensTheUnprefixedName(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	manager.cfg.RedirectURL = "https://app.test/auth/oidc/callback"
	manager.cfg.AcceptLegacyCookie = true
	token := issue(t, manager, 1)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: token})
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("the legacy cookie was refused although the migration is on: %d", recorder.Code)
	}
}

// Behind Traefik the TLS terminates at the proxy, so r.TLS is nil on every
// production request. Three apps derive the flag from the success URL and get
// this wrong in exactly the deployment that matters.
func TestSecureFlagFollowsTheForwardedProto(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if isSecure(plain) {
		t.Fatal("a plain request was marked secure")
	}
	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "HTTPS")
	if !isSecure(proxied) {
		t.Fatal("a request proxied over https was marked insecure")
	}
}

// A cookie without the __Host- prefix is one a sibling host can forge: the
// server cannot tell a host-only cookie from a Domain=example.com one of the
// same name, so an app next door can fix a victim into its own session.
func TestSessionCookieIsHostPrefixedBehindTLS(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	manager.cfg.RedirectURL = "https://app.test/auth/oidc/callback"

	recorder := httptest.NewRecorder()
	manager.SetSessionCookie(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "the-token")

	cookie := recorder.Result().Cookies()[0]
	if cookie.Name != "__Host-"+porte.SessionCookieName {
		t.Fatalf("cookie name = %q, want the __Host- prefixed form", cookie.Name)
	}
	// The prefix is only honoured by a browser when all three hold.
	if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("cookie = %+v, which a browser would reject under the __Host- prefix", cookie)
	}
}

// Over plain http the browser rejects the prefixed name outright, so local
// development keeps the bare one.
func TestSessionCookieDropsThePrefixWithoutTLS(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	manager.cfg.RedirectURL = "http://localhost:5173/auth/oidc/callback"
	manager.cfg.SuccessURL = "http://localhost:5173/"

	recorder := httptest.NewRecorder()
	manager.SetSessionCookie(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "the-token")

	cookie := recorder.Result().Cookies()[0]
	if cookie.Name != porte.SessionCookieName {
		t.Fatalf("cookie name = %q, want the bare name over http", cookie.Name)
	}
}

// The Secure attribute is derived from the configuration as well as the
// request, so a proxy that stops sending X-Forwarded-Proto cannot downgrade
// the session cookie to plaintext.
func TestConfiguredHTTPSForcesTheSecureAttribute(t *testing.T) {
	manager := testManager(t, newMemory(), time.Now())
	manager.cfg.RedirectURL = "https://app.test/auth/oidc/callback"

	recorder := httptest.NewRecorder()
	// No TLS, no X-Forwarded-Proto: the misconfigured-proxy case.
	manager.SetSessionCookie(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "the-token")

	if cookie := recorder.Result().Cookies()[0]; !cookie.Secure {
		t.Fatal("the session cookie was written without Secure although the app is configured for https")
	}
}

// Ending a session is session management, not OIDC. An app running without a
// provider still has sessions to end, and mounting this only alongside the
// OIDC routes forced it to keep a second logout handler and a second response
// shape until the day it switched SSO on.
func TestLogoutIsMountedWithoutAnyProvider(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	token := issue(t, manager, 7)

	router := chi.NewRouter()
	manager.Mount(router)

	request := httptest.NewRequest(http.MethodPost, porte.RouteLogout, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("logout returned %d: %s", recorder.Code, recorder.Body)
	}
	if _, err := store.Find(context.Background(), porte.HashToken(token)); err == nil {
		t.Fatal("the session survived the logout")
	}
}

// Logging out has to work in the state that makes somebody want to: a session
// the server has already stopped honouring, in a browser that still holds the
// cookie. Behind RequireAuth that request 401s and the cookie survives, so the
// user presses a button that fails while the stale cookie keeps being sent.
func TestLogoutClearsAStaleCookieInsteadOfRefusingIt(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())

	router := chi.NewRouter()
	manager.Mount(router)

	request := httptest.NewRequest(http.MethodPost, porte.RouteLogout, nil)
	request.AddCookie(sessionCookie(manager, "a-session-that-no-longer-exists"))
	request.Header.Set(porte.CSRFHeaderName, "1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("logout with a stale cookie returned %d: %s", recorder.Code, recorder.Body)
	}
	var cleared bool
	for _, cookie := range recorder.Result().Cookies() {
		if strings.Contains(cookie.Name, porte.SessionCookieName) && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the stale cookie was left in the browser, so the next request still sends it")
	}
}

// Widening the route must not drop the protection it had. Optional swallows
// the CSRF refusal Authenticate raises, so the check is the handler's own —
// without it a cross-site POST logs the victim out.
func TestLogoutStillRefusesACookieWithoutTheCSRFHeader(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	token := issue(t, manager, 7)

	router := chi.NewRouter()
	manager.Mount(router)

	request := httptest.NewRequest(http.MethodPost, porte.RouteLogout, nil)
	request.AddCookie(sessionCookie(manager, token))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a forged logout returned %d, want 403", recorder.Code)
	}
	if _, err := store.Find(context.Background(), porte.HashToken(token)); err != nil {
		t.Fatal("a forged logout ended the session")
	}
}

// Optional serves a route that has both a signed-in and an anonymous caller —
// a public share link that shows an edit button to its owner.
func TestOptionalAttachesAnIdentityWhenThereIsOneAndLetsAnonymousThrough(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	token := issue(t, manager, 42)

	handler := manager.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := porte.From(r.Context())
		if !ok {
			_, _ = w.Write([]byte("anonymous"))
			return
		}
		_, _ = w.Write([]byte(strconv.FormatInt(identity.UserID, 10)))
	}))

	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/", nil))
	if anonymous.Code != http.StatusOK || anonymous.Body.String() != "anonymous" {
		t.Fatalf("anonymous request = %d %q, want 200 anonymous", anonymous.Code, anonymous.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	signedIn := httptest.NewRecorder()
	handler.ServeHTTP(signedIn, request)
	if signedIn.Code != http.StatusOK || signedIn.Body.String() != "42" {
		t.Fatalf("signed-in request = %d %q, want 200 42", signedIn.Code, signedIn.Body.String())
	}

	// A bad credential is not a 401 here, but it must not authenticate
	// either — the route is public, the caller is simply not identified.
	bad := httptest.NewRequest(http.MethodGet, "/", nil)
	bad.Header.Set("Authorization", "Bearer not-a-real-token")
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, bad)
	if rejected.Body.String() != "anonymous" {
		t.Fatalf("an invalid token yielded %q, want anonymous", rejected.Body.String())
	}
}

// This is the method v0.1 was missing: an app with its own password login mints
// a porte session and gets porte's cookie, so the next request authenticates
// through the same middleware, the same CSRF rule and the same idle window as a
// federated login does.
func TestIssueCookieMintsASessionTheNextRequestAuthenticates(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())

	login := httptest.NewRecorder()
	token, session, err := manager.IssueCookie(context.Background(), login,
		httptest.NewRequest(http.MethodPost, "/login", nil), 7)
	if err != nil {
		t.Fatalf("IssueCookie: %v", err)
	}
	if token == "" || session.UserID != 7 {
		t.Fatalf("IssueCookie gave %q %+v, want a token for user 7", token, session)
	}

	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != token {
		t.Fatalf("cookies = %+v, want one carrying the plaintext token", cookies)
	}

	// The browser sends exactly what was set, and it authenticates.
	request := httptest.NewRequest(http.MethodGet, "/x", nil)
	request.AddCookie(cookies[0])
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("the cookie IssueCookie set = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}

	var identity porte.Identity
	if err := json.Unmarshal(recorder.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if identity.UserID != 7 || identity.SessionID != session.ID {
		t.Fatalf("identity = %+v, want the session that was just issued", identity)
	}
}

// A logout that only expires the cookie leaves a live row anyone holding the
// token can keep using, so Clear has to do both halves.
func TestClearDeletesTheRowAndExpiresTheCookie(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())
	token := issue(t, manager, 7)

	stored, err := store.Find(context.Background(), porte.HashToken(token))
	if err != nil {
		t.Fatalf("the session was not stored: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(sessionCookie(manager, token))
	request = request.WithContext(porte.WithIdentity(request.Context(),
		porte.Identity{UserID: 7, SessionID: stored.ID}))
	recorder := httptest.NewRecorder()
	if err := manager.Clear(request.Context(), recorder, request); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if _, err := store.Find(context.Background(), porte.HashToken(token)); err == nil {
		t.Fatal("the session row survived Clear")
	}
	cleared := false
	for _, cookie := range recorder.Result().Cookies() {
		if strings.HasSuffix(cookie.Name, porte.SessionCookieName) && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("Clear did not expire the session cookie: %+v", recorder.Result().Cookies())
	}
}

// An app that names a session — an API token — has to be able to list and
// revoke it without also holding the store. The second adopter needed both and
// the manager exposed neither.
func TestListAndRevokeReachTheUsersSessions(t *testing.T) {
	store := newMemory()
	manager := testManager(t, store, time.Now())

	interactive := issue(t, manager, 7)
	named, _, err := manager.Issue(context.Background(), 7, "CLI")
	if err != nil {
		t.Fatalf("issue a labelled session: %v", err)
	}

	held, err := manager.List(context.Background(), 7)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("expected two sessions, got %d", len(held))
	}

	var token porte.Session
	for _, candidate := range held {
		if candidate.IsAPIToken() {
			token = candidate
		}
	}
	if token.Label != "CLI" {
		t.Fatalf("the labelled session did not come back: %+v", held)
	}

	if err := manager.Revoke(context.Background(), 7, token.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.Find(context.Background(), porte.HashToken(named)); err == nil {
		t.Fatal("the revoked token still authenticates")
	}
	if _, err := store.Find(context.Background(), porte.HashToken(interactive)); err != nil {
		t.Fatal("revoking the API token also ended the interactive session")
	}
}

// An app running a cleanup worker should not have to hold the store as well as
// the manager just to expire rows.
func TestSweepDeletesExpiredSessionsAndSparesLabelledOnes(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)

	live := issue(t, manager, 7)
	token, _, err := manager.Issue(context.Background(), 7, "nightly job")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Past the absolute lifetime, so the browser session is expired and the
	// labelled one — which never gets an expiry — is not.
	manager.now = func() time.Time { return now.Add(porte.DefaultSessionTTL + time.Hour) }
	if _, err := manager.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if _, err := store.Find(context.Background(), porte.HashToken(live)); err == nil {
		t.Error("the expired browser session survived the sweep")
	}
	if _, err := store.Find(context.Background(), porte.HashToken(token)); err != nil {
		t.Error("the sweep took a named API token, which has no expiry to be past")
	}
}

// A named API token has no expiry, which is what the store's sweeper, the idle
// window and every adoption's migration already assumed. Issue used to stamp
// the 30-day session lifetime onto it, so a token minted in the UI died a month
// later while a migrated one lived forever.
func TestANamedTokenIsIssuedWithoutAnExpiry(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager := testManager(t, store, now)

	_, login, err := manager.Issue(context.Background(), 7, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if login.ExpiresAt.IsZero() {
		t.Fatal("a browser session was issued with no expiry")
	}

	_, token, err := manager.Issue(context.Background(), 7, "nightly job")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !token.ExpiresAt.IsZero() {
		t.Fatalf("a named token was given an expiry (%v), so it dies a month after it is created", token.ExpiresAt)
	}
}
