package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"

	"github.com/go-chi/chi/v5"
)

// memory is the session store in a map, small enough to build a session
// manager on. The credential itself is tested in porte/session, which owns it;
// this one only exists so the OIDC routes have somewhere to issue into.
type memory struct {
	mu       sync.Mutex
	sessions map[string]porte.Session
	codes    map[string]porte.LoginCode
	nextID   int64
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

func (m *memory) DeleteLogins(_ context.Context, userID, except int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	for hash, session := range m.sessions {
		if session.UserID != userID || session.Label != "" {
			continue
		}
		if except != 0 && session.ID == except {
			continue
		}
		delete(m.sessions, hash)
		deleted++
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

// testManager is the session manager the kit issues through, over the same
// clock the kit reads.
func testManager(t *testing.T, store *memory, now func() time.Time) *session.Manager {
	t.Helper()
	manager, err := session.New(porte.Config{SuccessURL: "https://app.test/"}, session.Deps{
		Sessions: store,
		Logger:   slog.New(slog.DiscardHandler),
		Now:      now,
	})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	return manager
}

func testKit(t *testing.T, store *memory, now time.Time) *Kit {
	t.Helper()
	manager := testManager(t, store, func() time.Time { return now })
	return &Kit{
		cfg:      porte.Config{SuccessURL: "https://app.test/"}.Resolved(),
		deps:     Deps{Sessions: manager, Codes: codes{store}},
		sessions: manager,
		logger:   slog.New(slog.DiscardHandler),
		now:      func() time.Time { return now },
	}
}

func TestALoginCodeWorksOnceAndOnlyOnce(t *testing.T) {
	now := time.Now()
	store := newMemory()
	kit := testKit(t, store, now)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/cb", nil)
	kit.issueLoginCode(recorder, request, 7, "", "")

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
	kit := testKit(t, store, now)

	recorder := httptest.NewRecorder()
	kit.issueLoginCode(recorder, httptest.NewRequest(http.MethodGet, "/cb", nil), 7, "", "")
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

func TestEmailClaimTrust(t *testing.T) {
	cases := map[string]struct {
		value              any
		want, wantTrusting bool
	}{
		"absent is an assertion of nothing": {nil, false, true},
		"true":                              {true, true, true},
		"false":                             {false, false, false},
		"the string false":                  {"false", false, false},
		"the string true":                   {"true", true, true},
		"the string 0":                      {"0", false, false},
		"a string nobody can read":          {"maybe", false, true},
		"anything unexpected":               {42, false, true},
	}
	for name, testCase := range cases {
		strict := testKit(t, newMemory(), time.Now())
		if got := strict.emailTrusted(testCase.value); got != testCase.want {
			t.Errorf("%s: emailTrusted(%v) = %v, want %v", name, testCase.value, got, testCase.want)
		}

		trusting := testKit(t, newMemory(), time.Now())
		trusting.cfg.TrustEmailWithoutVerifiedClaim = true
		if got := trusting.emailTrusted(testCase.value); got != testCase.wantTrusting {
			t.Errorf("%s, trusting an absent claim: emailTrusted(%v) = %v, want %v",
				name, testCase.value, got, testCase.wantTrusting)
		}
	}
}

// The flag answers "the provider said nothing". It must not answer "the
// provider said no" — that one is an assertion, and an operator overruling it
// is the account takeover the guard exists for, re-enabled by a checkbox.
func TestTrustingAnAbsentClaimDoesNotOverruleAnExplicitFalse(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())
	kit.cfg.TrustEmailWithoutVerifiedClaim = true
	for _, value := range []any{false, "false", "False", "FALSE", "0"} {
		if kit.emailTrusted(value) {
			t.Fatalf("emailTrusted(%v) trusted an address the provider refused to verify", value)
		}
	}
}

func TestConfigResponseIsServedWithOIDCDisabled(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())
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

// Every app in the suite serves a superset of porte's two keys at
// /auth/config, and porte owns the route, so an adopting app has to be able to
// keep its own key without registering the path a second time.
func TestConfigExtraAddsTheAppsOwnKeysAndCannotOverridePortes(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())
	kit.cfg.SSOOnly = true
	kit.deps.ConfigExtra = func() map[string]any {
		return map[string]any{"allow_registration": true, "sso_only": false, "oidc_enabled": true}
	}

	recorder := httptest.NewRecorder()
	kit.handleConfig(recorder, httptest.NewRequest(http.MethodGet, porte.RouteConfig, nil))

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["allow_registration"] != true {
		t.Fatalf("the app's own key did not survive: %+v", body)
	}
	if body["sso_only"] != true || body["oidc_enabled"] != false {
		t.Fatalf("the app overrode porte's own keys: %+v", body)
	}
}

// An unconfigured provider should mean no endpoint to probe rather than an
// endpoint that 500s, so RouteConfig is the only route Mount registers when
// OIDC is off.
func TestTheOIDCRoutesAreAbsentWhenOIDCIsDisabled(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())

	router := chi.NewRouter()
	kit.Mount(router)

	for _, route := range []string{porte.RouteLogin, porte.RouteSyncProfile} {
		probe := httptest.NewRequest(http.MethodGet, route, nil)
		result := httptest.NewRecorder()
		router.ServeHTTP(result, probe)
		if result.Code != http.StatusMethodNotAllowed && result.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d with OIDC disabled", route, result.Code)
		}
	}

	config := httptest.NewRecorder()
	router.ServeHTTP(config, httptest.NewRequest(http.MethodGet, porte.RouteConfig, nil))
	if config.Code != http.StatusOK {
		t.Fatalf("%s answered %d with OIDC disabled, want 200", porte.RouteConfig, config.Code)
	}
}

func extractCode(t *testing.T, page string) string {
	t.Helper()
	const opening = `<output id="c">`
	start := strings.Index(page, opening)
	end := strings.Index(page, "</output>")
	if start < 0 || end < start {
		t.Fatalf("no code in the success page: %s", page)
	}
	return page[start+len(opening) : end]
}

func quote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// The kit and the manager share one Config type but are built separately, and
// the fields deciding whether the session cookie is Secure live on the
// manager's copy. A typo in one of them would otherwise downgrade a security
// property with nothing failing.
func TestNewRefusesAKitAndManagerBuiltFromDifferentConfigs(t *testing.T) {
	store := newMemory()
	manager, err := session.New(porte.Config{SuccessURL: "https://app.test/"}, session.Deps{
		Sessions: store,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	_, err = New(context.Background(), porte.Config{SuccessURL: "https://typo.test/"}, Deps{Sessions: manager})
	if err == nil {
		t.Fatal("a kit was built against a manager configured for another host")
	}
	if !strings.Contains(err.Error(), "OIDC_SUCCESS_URL") {
		t.Fatalf("the error does not name the variable that disagrees: %v", err)
	}
}

// The code page is one of two places porte draws HTML instead of redirecting to
// the app, so it is the one page where porte owes the user the app's name: a
// page that names nobody is one they cannot tell from a phishing page that
// asked for the same login. It also carries the credential itself, which is
// what no-store is for (OAuth 2.1 §7.1).
//
// testKit's SuccessURL is https://app.test/, so both the name and the logo here
// are derived rather than configured.
func TestTheCodePageNamesTheAppAndRefusesToBeCached(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())

	recorder := httptest.NewRecorder()
	kit.issueLoginCode(recorder, httptest.NewRequest(http.MethodGet, "/cb", nil), 7, "", "")

	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on a response carrying a credential", got)
	}

	page := recorder.Body.String()
	if code := extractCode(t, page); code == "" {
		t.Error("the page carries no code, so there is nothing to paste")
	}
	if !strings.Contains(page, "<span>App</span>") {
		t.Errorf("the page does not name the app:\n%s", page)
	}
	if !strings.Contains(page, "https://app.test/logo.svg") {
		t.Errorf("the page carries no logo:\n%s", page)
	}
	if !strings.Contains(page, "valid for 60 seconds") {
		t.Errorf("the page does not say how long the code lasts:\n%s", page)
	}
}

// A CLI's nonce must come back on the loopback redirect, or its listener has
// no way to tell its own callback from one a local process raced in first.
func TestLoopbackRedirectEchoesTheCLINonce(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/cb", nil)
	kit.issueLoginCode(recorder, request, 7, "51234", "deadbeef")

	location := recorder.Header().Get("Location")
	target, err := url.Parse(location)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if target.Hostname() != "127.0.0.1" || target.Port() != "51234" {
		t.Fatalf("redirect went to %s, want loopback on 51234", location)
	}
	if got := target.Query().Get("state"); got != "deadbeef" {
		t.Fatalf("state is %q, want the nonce back", got)
	}
	if target.Query().Get("code") == "" {
		t.Fatal("the redirect carries no code")
	}
}

// A CLI that predates the nonce must keep working, or deploying this locks out
// every binary already installed.
func TestLoopbackRedirectOmitsStateWhenNoNonceWasSent(t *testing.T) {
	kit := testKit(t, newMemory(), time.Now())

	recorder := httptest.NewRecorder()
	kit.issueLoginCode(recorder, httptest.NewRequest(http.MethodGet, "/cb", nil), 7, "51234", "")

	target, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if _, present := target.Query()["state"]; present {
		t.Fatal("no nonce was sent, so none may be echoed")
	}
	if target.Query().Get("code") == "" {
		t.Fatal("the redirect carries no code")
	}
}

func TestCLIStateRejectsAnythingThatIsNotANonce(t *testing.T) {
	cases := map[string]string{
		"plain":       "deadbeef",
		"mixed":       "aZ09-_",
		"empty":       "",
		"ampersand":   "abc&code=stolen",
		"newline":     "abc\r\nX-Injected: 1",
		"space":       "abc def",
		"percent":     "abc%26",
		"overlong":    strings.Repeat("a", 129),
		"at the edge": strings.Repeat("a", 128),
	}
	valid := map[string]bool{"plain": true, "mixed": true, "at the edge": true}

	for name, input := range cases {
		got := cliState(input)
		if valid[name] && got != input {
			t.Errorf("%s: %q was rejected", name, input)
		}
		if !valid[name] && got != "" {
			t.Errorf("%s: %q was accepted as %q", name, input, got)
		}
	}
}
