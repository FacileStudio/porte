package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

// memory is every store porte needs, in a map. It exists so the middleware and
// the exchange can be tested without a database; the real ones are in porte/pg
// and are tested against a real PostgreSQL.
type memory struct {
	mu       sync.Mutex
	sessions map[string]porte.Session
	codes    map[string]porte.LoginCode
	nextID   int64
	touches  int
}

func newMemory() *memory {
	return &memory{sessions: map[string]porte.Session{}, codes: map[string]porte.LoginCode{}}
}

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

func (m *memory) ListByUser(context.Context, int64) ([]porte.Session, error) { return nil, nil }

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

func (m *memory) DeleteExpired(context.Context, time.Time) (int64, error) { return 0, nil }

type codes struct{ *memory }

func (c codes) Create(_ context.Context, code porte.LoginCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codes[code.CodeHash] = code
	return nil
}

func (c codes) Consume(_ context.Context, codeHash string) (porte.LoginCode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	code, ok := c.codes[codeHash]
	if !ok {
		return porte.LoginCode{}, porte.ErrNotFound
	}
	delete(c.codes, codeHash)
	return code, nil
}

func (c codes) DeleteExpired(context.Context, time.Time) (int64, error) { return 0, nil }

func testKit(store *memory, now time.Time) *Kit {
	return &Kit{
		cfg:    porte.Config{SuccessURL: "https://app.test/"}.Resolved(),
		deps:   Deps{Sessions: store, Codes: codes{store}},
		logger: slog.New(slog.DiscardHandler),
		now:    func() time.Time { return now },
	}
}

// issue puts a live session in the store and returns its plaintext token.
func issue(t *testing.T, kit *Kit, userID int64) string {
	t.Helper()
	token, _, err := kit.issueSession(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("issueSession: %v", err)
	}
	return token
}

func authenticated(kit *Kit) http.Handler {
	return kit.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := porte.From(r.Context())
		_ = json.NewEncoder(w).Encode(identity)
	}))
}

func TestCookieTransportRequiresTheCSRFHeaderOnMutatingRequests(t *testing.T) {
	now := time.Now()
	store := newMemory()
	kit := testKit(store, now)
	token := issue(t, kit, 7)

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
			request.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: token})
			if testCase.header {
				request.Header.Set(porte.CSRFHeaderName, "1")
			}
			recorder := httptest.NewRecorder()
			authenticated(kit).ServeHTTP(recorder, request)
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
	kit := testKit(store, now)

	request := httptest.NewRequest(http.MethodPost, "/x", nil)
	request.Header.Set("Authorization", "Bearer "+issue(t, kit, 7))
	recorder := httptest.NewRecorder()
	authenticated(kit).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", recorder.Code, recorder.Body)
	}
}

func TestNoCredentialIsReadFromTheQueryString(t *testing.T) {
	now := time.Now()
	store := newMemory()
	kit := testKit(store, now)
	token := issue(t, kit, 7)

	for _, param := range []string{"token", "api_key", "access_token"} {
		request := httptest.NewRequest(http.MethodGet, "/x?"+param+"="+token, nil)
		recorder := httptest.NewRecorder()
		authenticated(kit).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("?%s= authenticated the request (status %d)", param, recorder.Code)
		}
	}
}

func TestExpiredSessionIsRefusedAndTheCookieCleared(t *testing.T) {
	now := time.Now()
	store := newMemory()
	kit := testKit(store, now)
	token := issue(t, kit, 7)

	kit.now = func() time.Time { return now.Add(porte.DefaultSessionTTL + time.Second) }

	request := httptest.NewRequest(http.MethodGet, "/x", nil)
	request.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: token})
	recorder := httptest.NewRecorder()
	authenticated(kit).ServeHTTP(recorder, request)

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
	kit := testKit(store, now)
	token := issue(t, kit, 7)

	send := func() {
		request := httptest.NewRequest(http.MethodGet, "/x", nil)
		request.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: token})
		authenticated(kit).ServeHTTP(httptest.NewRecorder(), request)
	}
	send()
	send()
	if store.touches != 0 {
		t.Fatalf("touched %d times inside the interval, want 0", store.touches)
	}

	kit.now = func() time.Time { return now.Add(touchInterval + time.Second) }
	send()
	if store.touches != 1 {
		t.Fatalf("touched %d times after the interval, want 1", store.touches)
	}
}

func TestTheSessionTokenIsNeverStoredInThePlain(t *testing.T) {
	store := newMemory()
	kit := testKit(store, time.Now())
	token := issue(t, kit, 7)

	if _, ok := store.sessions[token]; ok {
		t.Fatal("the plaintext token is a key in the store")
	}
	if _, ok := store.sessions[porte.HashToken(token)]; !ok {
		t.Fatal("the session was not stored under its hash")
	}
}

func TestALoginCodeWorksOnceAndOnlyOnce(t *testing.T) {
	now := time.Now()
	store := newMemory()
	kit := testKit(store, now)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/cb", nil)
	kit.issueLoginCode(recorder, request, 7, "")

	code := extractCode(t, recorder.Body.String())

	exchange := func() *httptest.ResponseRecorder {
		out := httptest.NewRecorder()
		body := strings.NewReader(`{"code":` + quote(code) + `}`)
		kit.handleExchange(out, httptest.NewRequest(http.MethodPost, porte.RouteExchange, body))
		return out
	}

	first := exchange()
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange = %d, want 200 (%s)", first.Code, first.Body)
	}
	var response porte.ExchangeResponse
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.UserID != "7" || response.Token == "" {
		t.Fatalf("unexpected exchange response %+v", response)
	}

	if second := exchange(); second.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d, want 401", second.Code)
	}
}

func TestAnExpiredLoginCodeIsRefused(t *testing.T) {
	now := time.Now()
	store := newMemory()
	kit := testKit(store, now)

	recorder := httptest.NewRecorder()
	kit.issueLoginCode(recorder, httptest.NewRequest(http.MethodGet, "/cb", nil), 7, "")
	code := extractCode(t, recorder.Body.String())

	kit.now = func() time.Time { return now.Add(porte.DefaultLoginCodeTTL + time.Second) }

	out := httptest.NewRecorder()
	kit.handleExchange(out, httptest.NewRequest(http.MethodPost, porte.RouteExchange,
		strings.NewReader(`{"code":`+quote(code)+`}`)))
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", out.Code)
	}
}

// The CLI's loopback redirect takes only a port number from the request; the
// host is porte's. Anything else would be an open redirect on an endpoint that
// hands out a credential.
func TestLoopbackPortRejectsAnythingButAPort(t *testing.T) {
	for _, value := range []string{"", "0", "80", "443", "70000", "-1", "8080evil.com", "8080 ", "٨٠٨٠"} {
		if got := loopbackPort(value); got != "" {
			t.Fatalf("loopbackPort(%q) = %q, want empty", value, got)
		}
	}
	if got := loopbackPort("53412"); got != "53412" {
		t.Fatalf("loopbackPort(53412) = %q", got)
	}
}

func TestFlowSurvivesACookieRoundTrip(t *testing.T) {
	original := flow{State: "s", Nonce: "n", Verifier: "v", CLI: true, Port: "53412"}
	encoded, err := original.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, ok := decodeFlow(encoded)
	if !ok || decoded != original {
		t.Fatalf("round trip gave %+v (ok=%v)", decoded, ok)
	}

	for _, broken := range []string{"", "!!!", "e30", "eyJzIjoiYSJ9"} {
		if _, ok := decodeFlow(broken); ok {
			t.Fatalf("decodeFlow(%q) accepted an incomplete flow", broken)
		}
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

func TestEmailClaimTrust(t *testing.T) {
	cases := map[string]struct {
		value any
		want  bool
	}{
		"absent is an assertion of nothing": {nil, true},
		"true":                              {true, true},
		"false":                             {false, false},
		"the string false":                  {"false", false},
		"the string true":                   {"true", true},
		"anything unexpected":               {42, false},
	}
	for name, testCase := range cases {
		if got := emailClaimTrusted(testCase.value); got != testCase.want {
			t.Errorf("%s: emailClaimTrusted(%v) = %v", name, testCase.value, got)
		}
	}
}

func TestConfigResponseIsServedWithOIDCDisabled(t *testing.T) {
	kit := testKit(newMemory(), time.Now())
	kit.cfg.SSOOnly = true

	recorder := httptest.NewRecorder()
	kit.handleConfig(recorder, httptest.NewRequest(http.MethodGet, porte.RouteConfig, nil))

	var response porte.ConfigResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !response.SSOOnly || response.OIDCEnabled {
		t.Fatalf("unexpected config response %+v", response)
	}
}

func extractCode(t *testing.T, page string) string {
	t.Helper()
	start := strings.Index(page, "<code>")
	end := strings.Index(page, "</code>")
	if start < 0 || end < start {
		t.Fatalf("no code in the success page: %s", page)
	}
	return page[start+len("<code>") : end]
}

func quote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
