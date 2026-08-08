package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"

	"github.com/go-chi/chi/v5"
)

// This file walks the flow end to end against an in-process identity provider
// that behaves like a strict, conformant issuer: it signs real RS256 tokens
// behind a real JWKS, and its token endpoint *enforces* PKCE, the redirect URI
// and client authentication rather than trusting the client to have sent them.
//
// SPEC §13 called PKCE, the nonce and the back-channel logout token "the three
// paths a unit test cannot honestly cover, because they are assertions about
// what the provider does". This provider makes those assertions itself: a kit
// that dropped its PKCE verifier, reused a nonce or accepted an ID token at
// the logout endpoint fails these tests.

// provider is the fake IdP. Everything it issues is signed with a throwaway
// RSA key served over its own JWKS endpoint, so the kit's verification path is
// the real one.
type provider struct {
	mu     sync.Mutex
	server *httptest.Server
	key    *rsa.PrivateKey

	// codes maps an issued authorization code to the request that earned it.
	codes map[string]authRequest

	// scopesSupported is what discovery advertises; tests shrink it to prove
	// the startup guard.
	scopesSupported []string

	// mintClaims lets a test tamper with the ID token after the honest
	// claims are assembled — a provider echoing the wrong nonce, say.
	mintClaims func(claims map[string]any)

	// subject and profile are what the provider asserts about the one user
	// who ever signs in here.
	subject string
	email   string
	name    string

	// userinfoSubject, when set, is the sub the UserInfo endpoint claims —
	// which a conformant relying party must compare against the ID token's.
	userinfoSubject string

	// roles, when non-nil, rides into the ID token as a flat roles claim.
	roles []string

	tokenRequests int
}

type authRequest struct {
	clientID    string
	redirectURI string
	state       string
	nonce       string
	challenge   string
	method      string
	scopes      []string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the provider key: %v", err)
	}
	idp := &provider{
		key:             key,
		codes:           map[string]authRequest{},
		scopesSupported: []string{"openid", "email", "profile", "offline_access", "facile"},
		subject:         "subject-1",
		email:           "user@example.test",
		name:            "Test User",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("/keys", idp.handleJWKS)
	mux.HandleFunc("/token", idp.handleToken)
	mux.HandleFunc("/userinfo", idp.handleUserinfo)
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (p *provider) issuer() string { return p.server.URL }

func (p *provider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	scopes := append([]string(nil), p.scopesSupported...)
	p.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.issuer(),
		"authorization_endpoint":                p.issuer() + "/authorize",
		"token_endpoint":                        p.issuer() + "/token",
		"jwks_uri":                              p.issuer() + "/keys",
		"userinfo_endpoint":                     p.issuer() + "/userinfo",
		"scopes_supported":                      scopes,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *provider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.Public().(*rsa.PublicKey)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": "test-key",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// authorize plays the user's half: it takes the URL the kit redirected the
// browser to, asserts everything a strict provider requires, and returns the
// callback URL carrying the code — exactly what the browser would be sent back
// with.
func (p *provider) authorize(t *testing.T, authURL string) (callback string) {
	t.Helper()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("unparseable authorization URL %q: %v", authURL, err)
	}
	q := parsed.Query()

	request := authRequest{
		clientID:    q.Get("client_id"),
		redirectURI: q.Get("redirect_uri"),
		state:       q.Get("state"),
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		method:      q.Get("code_challenge_method"),
		scopes:      strings.Fields(q.Get("scope")),
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want code", q.Get("response_type"))
	}
	if request.challenge == "" || request.method != "S256" {
		t.Fatalf("the kit did not send PKCE S256: challenge=%q method=%q", request.challenge, request.method)
	}
	if request.nonce == "" {
		t.Fatal("the kit did not send a nonce")
	}
	if request.state == "" {
		t.Fatal("the kit did not send a state")
	}
	hasOpenID := false
	for _, scope := range request.scopes {
		hasOpenID = hasOpenID || scope == "openid"
	}
	if !hasOpenID {
		t.Fatalf("scope %q does not include openid", q.Get("scope"))
	}

	code, err := porte.NewToken()
	if err != nil {
		t.Fatalf("minting a code: %v", err)
	}
	p.mu.Lock()
	p.codes[code] = request
	p.mu.Unlock()

	target, err := url.Parse(request.redirectURI)
	if err != nil {
		t.Fatalf("unparseable redirect_uri %q: %v", request.redirectURI, err)
	}
	values := url.Values{"code": {code}, "state": {request.state}}
	target.RawQuery = values.Encode()
	return target.String()
}

// handleToken is the strict half. It refuses a missing or wrong PKCE verifier,
// a changed redirect URI and bad client credentials — the checks a real
// provider performs and a fake that skips them would let regressions through.
func (p *provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.tokenRequests++
	p.mu.Unlock()

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID, clientSecret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if clientID != "test-client" || clientSecret != "test-secret" {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.mu.Lock()
		request, found := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		if !found {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		verifier := r.PostForm.Get("code_verifier")
		hashed := sha256.Sum256([]byte(verifier))
		if verifier == "" || base64.RawURLEncoding.EncodeToString(hashed[:]) != request.challenge {
			http.Error(w, `{"error":"invalid_grant","error_description":"PKCE verification failed"}`, http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("redirect_uri") != request.redirectURI {
			http.Error(w, `{"error":"invalid_grant","error_description":"redirect_uri mismatch"}`, http.StatusBadRequest)
			return
		}
		p.writeTokens(w, request.clientID, request.nonce)
	case "refresh_token":
		p.writeTokens(w, clientID, "")
	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
	}
}

func (p *provider) writeTokens(w http.ResponseWriter, audience, nonce string) {
	now := time.Now()
	claims := map[string]any{
		"iss":                p.issuer(),
		"sub":                p.subject,
		"aud":                audience,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"email":              p.email,
		"email_verified":     true,
		"name":               p.name,
		"preferred_username": "tester",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	p.mu.Lock()
	if p.roles != nil {
		claims["roles"] = p.roles
	}
	mutate := p.mintClaims
	p.mu.Unlock()
	if mutate != nil {
		mutate(claims)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "refresh-token",
		"id_token":      p.sign(claims),
	})
}

func (p *provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	p.mu.Lock()
	subject := p.userinfoSubject
	p.mu.Unlock()
	if subject == "" {
		subject = p.subject
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":            subject,
		"email":          p.email,
		"email_verified": true,
		"name":           p.name,
	})
}

// sign produces a compact RS256 JWT the kit's JWKS-backed verifier accepts.
func (p *provider) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// logoutToken mints a Back-Channel Logout 1.0 token for the provider's user.
// mutate tampers with it after the honest claims are assembled.
func (p *provider) logoutToken(mutate func(map[string]any)) string {
	now := time.Now()
	claims := map[string]any{
		"iss": p.issuer(),
		"sub": p.subject,
		"aud": "test-client",
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"jti": "logout-1",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if mutate != nil {
		mutate(claims)
	}
	return p.sign(claims)
}

// flowStores is the full store set the flow needs, in memory.
type flowStores struct {
	*memory
	mu         sync.Mutex
	users      map[string]int64
	nextUser   int64
	lastClaims porte.Claims
	identities map[string]porte.StoredIdentity
}

func newFlowStores() *flowStores {
	return &flowStores{
		memory:     newMemory(),
		users:      map[string]int64{},
		identities: map[string]porte.StoredIdentity{},
	}
}

func (s *flowStores) UpsertFromOIDC(_ context.Context, claims porte.Claims) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastClaims = claims
	key := claims.Provider + "\x00" + claims.Subject
	if id, ok := s.users[key]; ok {
		return id, nil
	}
	s.nextUser++
	s.users[key] = s.nextUser
	return s.nextUser, nil
}

type identityStore struct{ *flowStores }

func (s identityStore) Find(_ context.Context, provider, subject string) (porte.StoredIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.identities[provider+"\x00"+subject]
	if !ok {
		return porte.StoredIdentity{}, porte.ErrNotFound
	}
	return identity, nil
}

func (s identityStore) Save(_ context.Context, identity porte.StoredIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[identity.Provider+"\x00"+identity.Subject] = identity
	return nil
}

func (s identityStore) MarkRolesSynced(_ context.Context, provider, subject string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + "\x00" + subject
	identity, ok := s.identities[key]
	if !ok {
		return porte.ErrNotFound
	}
	identity.RolesSyncedAt = at
	s.identities[key] = identity
	return nil
}

func (s identityStore) ListByUser(_ context.Context, userID int64) ([]porte.StoredIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []porte.StoredIdentity
	for _, identity := range s.identities {
		if identity.UserID == userID {
			out = append(out, identity)
		}
	}
	return out, nil
}

// harness wires a real kit — discovery and all — to the fake provider and
// mounts it on a real chi router behind a test server.
type harness struct {
	idp    *provider
	kit    *Kit
	app    *httptest.Server
	stores *flowStores

	// clock is the kit's notion of now, so a test can step past a rate
	// limit without sleeping through it.
	clockMu sync.Mutex
	clock   time.Time
}

func (h *harness) advance(by time.Duration) {
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	h.clock = h.clock.Add(by)
}

func (h *harness) now() time.Time {
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	return h.clock
}

func newHarness(t *testing.T, configure func(*porte.Config)) *harness {
	t.Helper()
	idp := newProvider(t)
	stores := newFlowStores()

	router := chi.NewRouter()
	app := httptest.NewServer(router)
	t.Cleanup(app.Close)

	cfg := porte.Config{
		Issuer:       idp.issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  app.URL + porte.RouteCallback,
		SuccessURL:   app.URL + "/welcome",
	}
	if configure != nil {
		configure(&cfg)
	}

	kit, err := New(context.Background(), cfg, Deps{
		Users:      stores,
		Identities: identityStore{stores},
		Sessions:   stores.memory,
		Codes:      codes{stores.memory},
		Logger:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &harness{idp: idp, kit: kit, app: app, stores: stores, clock: time.Now()}
	kit.now = h.now

	kit.Mount(router)
	router.Group(func(r chi.Router) {
		r.Use(kit.RequireAuth)
		r.Get("/whoami", func(w http.ResponseWriter, r *http.Request) {
			identity, _ := porte.From(r.Context())
			_ = json.NewEncoder(w).Encode(identity)
		})
	})
	return h
}

// client returns an HTTP client that keeps cookies and never follows
// redirects, so each hop of the flow is observable.
func (h *harness) client(t *testing.T) *http.Client {
	t.Helper()
	jar := newCookieJar()
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// login walks the browser flow up to and including the callback and returns
// the callback response, with the client's jar holding whatever was set.
func (h *harness) login(t *testing.T, client *http.Client, loginQuery string) *http.Response {
	t.Helper()
	response, err := client.Get(h.app.URL + porte.RouteLogin + loginQuery)
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", response.StatusCode)
	}

	callback := h.idp.authorize(t, response.Header.Get("Location"))
	response, err = client.Get(callback)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = response.Body.Close()
	return response
}

func TestBrowserLoginFlowEndToEnd(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)

	callback := h.login(t, client, "")
	if callback.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", callback.StatusCode)
	}
	if got := callback.Header.Get("Location"); got != h.app.URL+"/welcome" {
		t.Fatalf("callback redirects to %q, want the success URL", got)
	}

	// The session cookie authenticates, and carries the provider's claims
	// through the upsert.
	request, _ := http.NewRequest(http.MethodGet, h.app.URL+"/whoami", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("whoami with the session cookie = %d, want 200", response.StatusCode)
	}

	h.stores.mu.Lock()
	claims := h.stores.lastClaims
	h.stores.mu.Unlock()
	if claims.Subject != "subject-1" || claims.Email != "user@example.test" || !claims.EmailVerified {
		t.Fatalf("upserted claims = %+v, want the provider's assertions", claims)
	}
	if claims.Provider != h.idp.issuer() {
		t.Fatalf("claims.Provider = %q, want the issuer", claims.Provider)
	}

	// The identity row exists under (provider, subject) with the tokens.
	stored, err := identityStore{h.stores}.Find(context.Background(), h.idp.issuer(), "subject-1")
	if err != nil {
		t.Fatalf("identity row missing after the callback: %v", err)
	}
	if stored.Tokens.RefreshToken == "" {
		t.Fatal("the refresh token did not reach the identity row")
	}
}

func TestCallbackRefusesAWrongNonce(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.mintClaims = func(claims map[string]any) { claims["nonce"] = "not-the-one-we-sent" }

	callback := h.login(t, h.client(t), "")
	if callback.StatusCode != http.StatusUnauthorized {
		t.Fatalf("callback with a wrong nonce = %d, want 401", callback.StatusCode)
	}
}

func TestCallbackRefusesATamperedState(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)

	response, err := client.Get(h.app.URL + porte.RouteLogin)
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	_ = response.Body.Close()
	callback := h.idp.authorize(t, response.Header.Get("Location"))

	tampered, _ := url.Parse(callback)
	q := tampered.Query()
	q.Set("state", "attacker-chosen")
	tampered.RawQuery = q.Encode()

	response, err = client.Get(tampered.String())
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback with a tampered state = %d, want 400", response.StatusCode)
	}
}

func TestCallbackWithoutTheFlowCookieIsRefused(t *testing.T) {
	h := newHarness(t, nil)

	// A bare client with no jar: the state cookie never comes back, which is
	// also what a cross-site request forging the callback looks like.
	response, err := http.Get(h.app.URL + porte.RouteCallback + "?code=x&state=y")
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback without the flow cookie = %d, want 400", response.StatusCode)
	}
}

func TestCLILoginFlowEndToEnd(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)

	callback := h.login(t, client, "?"+porte.FlowParam+"="+porte.FlowCLI)
	if callback.StatusCode != http.StatusOK {
		t.Fatalf("CLI callback = %d, want the code page", callback.StatusCode)
	}

	// The page carries the code; a CLI's user pastes it. From the store's
	// perspective exactly one pending code must exist, stored as a hash.
	h.stores.memory.mu.Lock()
	defer h.stores.memory.mu.Unlock()
	if len(h.stores.codes) != 1 {
		t.Fatalf("pending codes = %d, want 1", len(h.stores.codes))
	}
	for hash := range h.stores.codes {
		if len(hash) != 64 {
			t.Fatalf("the pending code is stored as %q, want a hex SHA-256 hash", hash)
		}
	}
}

func TestCLIExchangeIssuesABearerThatAuthenticates(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)

	// Walk the CLI flow with a loopback port: the callback redirects to
	// 127.0.0.1 with the code in the query, which is where the plaintext is
	// observable without scraping HTML.
	response, err := client.Get(h.app.URL + porte.RouteLogin + "?flow=cli&port=8123")
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	_ = response.Body.Close()
	callbackURL := h.idp.authorize(t, response.Header.Get("Location"))
	response, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("CLI callback with a port = %d, want 302", response.StatusCode)
	}
	redirect, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("unparseable loopback redirect: %v", err)
	}
	if redirect.Host != "127.0.0.1:8123" {
		t.Fatalf("loopback redirect goes to %q, want 127.0.0.1:8123", redirect.Host)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("the loopback redirect carries no code")
	}

	// The exchange: code in, bearer out.
	body := strings.NewReader(fmt.Sprintf(`{"code":%q}`, code))
	response, err = http.Post(h.app.URL+porte.RouteExchange, "application/json", body)
	if err != nil {
		t.Fatalf("POST exchange: %v", err)
	}
	var exchanged porte.ExchangeResponse
	if err := json.NewDecoder(response.Body).Decode(&exchanged); err != nil {
		t.Fatalf("decoding the exchange response: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || exchanged.Token == "" {
		t.Fatalf("exchange = %d %+v, want 200 with a token", response.StatusCode, exchanged)
	}

	// The bearer authenticates without any cookie or CSRF header.
	request, _ := http.NewRequest(http.MethodGet, h.app.URL+"/whoami", nil)
	request.Header.Set("Authorization", "Bearer "+exchanged.Token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("whoami with the bearer = %d, want 200", response.StatusCode)
	}

	// A replayed code finds nothing.
	body = strings.NewReader(fmt.Sprintf(`{"code":%q}`, code))
	response, err = http.Post(h.app.URL+porte.RouteExchange, "application/json", body)
	if err != nil {
		t.Fatalf("POST exchange replay: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed exchange = %d, want 401", response.StatusCode)
	}
}

func TestBackchannelLogoutRevokesTheSessions(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)
	_ = h.login(t, client, "")

	// The session works before the logout.
	request, _ := http.NewRequest(http.MethodGet, h.app.URL+"/whoami", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("whoami before the logout = %d, want 200", response.StatusCode)
	}

	// The IdP announces the logout over the back channel.
	form := url.Values{"logout_token": {h.idp.logoutToken(nil)}}
	response, err = http.PostForm(h.app.URL+porte.RouteBackchannelLogout, form)
	if err != nil {
		t.Fatalf("POST backchannel-logout: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("backchannel logout = %d, want 200", response.StatusCode)
	}

	// The session is dead.
	request, _ = http.NewRequest(http.MethodGet, h.app.URL+"/whoami", nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("whoami after the back-channel logout = %d, want 401", response.StatusCode)
	}
}

func TestBackchannelLogoutRefusesAnIDToken(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)
	_ = h.login(t, client, "")

	// An ID token carries a nonce and no events claim. Accepting one here
	// would let anyone holding their own ID token log out anybody.
	token := h.idp.logoutToken(func(claims map[string]any) {
		claims["nonce"] = "some-nonce"
	})
	response, err := http.PostForm(h.app.URL+porte.RouteBackchannelLogout, url.Values{"logout_token": {token}})
	if err != nil {
		t.Fatalf("POST backchannel-logout: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logout with a nonce-carrying token = %d, want 401", response.StatusCode)
	}

	token = h.idp.logoutToken(func(claims map[string]any) {
		delete(claims, "events")
	})
	response, err = http.PostForm(h.app.URL+porte.RouteBackchannelLogout, url.Values{"logout_token": {token}})
	if err != nil {
		t.Fatalf("POST backchannel-logout: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logout without the events claim = %d, want 401", response.StatusCode)
	}
}

func TestBackchannelLogoutForAnUnknownSubjectRevealsNothing(t *testing.T) {
	h := newHarness(t, nil)
	token := h.idp.logoutToken(func(claims map[string]any) {
		claims["sub"] = "never-signed-in-here"
	})
	response, err := http.PostForm(h.app.URL+porte.RouteBackchannelLogout, url.Values{"logout_token": {token}})
	if err != nil {
		t.Fatalf("POST backchannel-logout: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("logout for an unknown subject = %d, want the same 200 as a known one", response.StatusCode)
	}
}

func TestRolesClaimRidesTheFlowWhenConfigured(t *testing.T) {
	h := newHarness(t, func(cfg *porte.Config) { cfg.ClaimsScope = "facile" })
	h.idp.roles = []string{"admin", "billing"}
	client := h.client(t)
	_ = h.login(t, client, "")

	request, _ := http.NewRequest(http.MethodGet, h.app.URL+"/whoami", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var identity porte.Identity
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatalf("decoding the identity: %v", err)
	}
	if !identity.HasRole("admin") || !identity.HasRole("billing") {
		t.Fatalf("identity.Roles = %v, want the provider's roles", identity.Roles)
	}
}

func TestCallbackFailsLoudlyWhenTheRolesClaimNeverArrives(t *testing.T) {
	// The scope is advertised and configured, but the provider never emits
	// the claim — the half-configured provider the startup guard cannot see.
	h := newHarness(t, func(cfg *porte.Config) { cfg.ClaimsScope = "facile" })
	h.idp.roles = nil

	callback := h.login(t, h.client(t), "")
	if callback.StatusCode == http.StatusFound {
		t.Fatal("the callback succeeded although the roles claim never arrived — this is the silent-deny failure the guard exists for")
	}
}

func TestNewRefusesARolesScopeTheProviderDoesNotOffer(t *testing.T) {
	idp := newProvider(t)
	idp.scopesSupported = []string{"openid", "email", "profile"}

	_, err := New(context.Background(), porte.Config{
		Issuer:       idp.issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.test/auth/oidc/callback",
		SuccessURL:   "https://app.test/",
		ClaimsScope:  "facile",
	}, Deps{Users: newFlowStores(), Identities: identityStore{newFlowStores()}, Sessions: newMemory(), Codes: codes{newMemory()}})
	if err == nil {
		t.Fatal("New accepted a roles scope the provider does not offer")
	}
}

// cookieJar is the minimal jar the flow needs: it files cookies by host and
// sends them back, which is what a browser does for the app's own origin.
type cookieJar struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}

func newCookieJar() *cookieJar { return &cookieJar{cookies: map[string][]*http.Cookie{}} }

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, cookie := range cookies {
		kept := j.cookies[u.Host][:0]
		for _, existing := range j.cookies[u.Host] {
			if existing.Name != cookie.Name {
				kept = append(kept, existing)
			}
		}
		if cookie.MaxAge >= 0 {
			kept = append(kept, cookie)
		}
		j.cookies[u.Host] = kept
	}
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]*http.Cookie(nil), j.cookies[u.Host]...)
}

// syncProfile is the authenticated POST an app's frontend makes to refresh a
// profile from the IdP. It carries the CSRF header because it is a cookie
// request that mutates.
func (h *harness) syncProfile(t *testing.T, client *http.Client) *http.Response {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, h.app.URL+porte.RouteSyncProfile, nil)
	request.Header.Set(porte.CSRFHeaderName, "1")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST sync-profile: %v", err)
	}
	return response
}

// OpenID Connect Core §5.3.2 makes this a MUST, and go-oidc does not do it for
// you: without the check, a UserInfo response for somebody else rewrites this
// user's email — which is the key the rest of the suite joins on.
func TestSyncProfileRefusesAUserinfoResponseForAnotherSubject(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)
	_ = h.login(t, client, "")

	h.idp.mu.Lock()
	h.idp.userinfoSubject = "somebody-else"
	h.idp.mu.Unlock()
	h.advance(porte.DefaultProfileSyncInterval + time.Minute)

	response := h.syncProfile(t, client)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sync-profile with a mismatched userinfo sub = %d, want 401", response.StatusCode)
	}

	h.stores.mu.Lock()
	defer h.stores.mu.Unlock()
	if h.stores.lastClaims.Subject != "subject-1" {
		t.Fatalf("the mismatched response reached the upsert: %+v", h.stores.lastClaims)
	}
}

func TestSyncProfileAcceptsAMatchingSubject(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)
	_ = h.login(t, client, "")

	h.idp.mu.Lock()
	h.idp.name = "Renamed In The IdP"
	h.idp.mu.Unlock()
	h.advance(porte.DefaultProfileSyncInterval + time.Minute)

	response := h.syncProfile(t, client)
	defer func() { _ = response.Body.Close() }()
	var synced porte.SyncProfileResponse
	if err := json.NewDecoder(response.Body).Decode(&synced); err != nil {
		t.Fatalf("decoding the sync response: %v", err)
	}
	if response.StatusCode != http.StatusOK || !synced.Synced {
		t.Fatalf("sync-profile = %d %+v, want a successful sync", response.StatusCode, synced)
	}

	h.stores.mu.Lock()
	defer h.stores.mu.Unlock()
	if h.stores.lastClaims.Name != "Renamed In The IdP" {
		t.Fatalf("the refreshed name did not reach the upsert: %+v", h.stores.lastClaims)
	}
}

// A cookie without the __Host- prefix is one a sibling host can forge: the
// server cannot tell a host-only cookie from a Domain=example.com one of the
// same name, so an app next door can fix a victim into its own session.
func TestSessionCookieIsHostPrefixedBehindTLS(t *testing.T) {
	kit := testKit(newMemory(), time.Now())
	kit.cfg.RedirectURL = "https://app.test/auth/oidc/callback"

	recorder := httptest.NewRecorder()
	kit.setSessionCookie(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "the-token")

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
	kit := testKit(newMemory(), time.Now())
	kit.cfg.RedirectURL = "http://localhost:5173/auth/oidc/callback"
	kit.cfg.SuccessURL = "http://localhost:5173/"

	recorder := httptest.NewRecorder()
	kit.setSessionCookie(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "the-token")

	cookie := recorder.Result().Cookies()[0]
	if cookie.Name != porte.SessionCookieName {
		t.Fatalf("cookie name = %q, want the bare name over http", cookie.Name)
	}
}

// An app adopting porte has users holding its old `session` cookie. They keep
// authenticating; only what porte writes changes.
func TestALegacySessionCookieStillAuthenticates(t *testing.T) {
	store := newMemory()
	kit := testKit(store, time.Now())
	token := issue(t, kit, 7)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: token})
	recorder := httptest.NewRecorder()
	authenticated(kit).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("a legacy session cookie = %d, want 200", recorder.Code)
	}
}

// The Secure attribute is derived from the configuration as well as the
// request, so a proxy that stops sending X-Forwarded-Proto cannot downgrade
// the session cookie to plaintext.
func TestConfiguredHTTPSForcesTheSecureAttribute(t *testing.T) {
	kit := testKit(newMemory(), time.Now())
	kit.cfg.RedirectURL = "https://app.test/auth/oidc/callback"

	recorder := httptest.NewRecorder()
	// No TLS, no X-Forwarded-Proto: the misconfigured-proxy case.
	kit.setSessionCookie(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "the-token")

	if cookie := recorder.Result().Cookies()[0]; !cookie.Secure {
		t.Fatal("the session cookie was written without Secure although the app is configured for https")
	}
}
