package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"

	"golang.org/x/oauth2"
)

// refreshGate stands in front of the fake provider's token endpoint and
// scripts what a refresh grant answers. Every other grant goes through. The
// kit is pinned to one client-auth style for it, because oauth2 probes a
// token URL it has not seen with a second request when the first is refused,
// and the tests count requests.
type refreshGate struct {
	idp *provider

	mu      sync.Mutex
	refusal string
	outage  bool
	before  func()
	count   int
}

func (g *refreshGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "refresh_token" {
		g.idp.handleToken(w, r)
		return
	}
	g.mu.Lock()
	g.count++
	before, refusal, outage := g.before, g.refusal, g.outage
	g.mu.Unlock()
	if before != nil {
		before()
	}
	switch {
	case outage:
		http.Error(w, "down", http.StatusServiceUnavailable)
	case refusal != "":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": refusal})
	default:
		g.idp.handleToken(w, r)
	}
}

func (g *refreshGate) script(change func(g *refreshGate)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	change(g)
}

func (g *refreshGate) refreshes() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.count
}

func (g *refreshGate) grant(roles ...string) {
	g.idp.mu.Lock()
	defer g.idp.mu.Unlock()
	g.idp.roles = roles
}

// adminSession signs one person in with the admin role on an app that reads
// the roles claim, and returns the client holding their cookie.
func adminSession(t *testing.T) (*harness, *http.Client, *refreshGate) {
	t.Helper()
	h := newHarness(t, func(cfg *porte.Config) { cfg.ClaimsScope = "facile" })
	h.idp.roles = []string{"admin"}
	client := h.client(t)
	h.login(t, client, "")
	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles after sign-in = %v, want admin", roles)
	}
	gate := &refreshGate{idp: h.idp}
	server := httptest.NewServer(gate)
	t.Cleanup(server.Close)
	h.kit.oauth.Endpoint.TokenURL = server.URL
	h.kit.oauth.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return h, client, gate
}

func cookieIdentity(t *testing.T, h *harness, client *http.Client) porte.Identity {
	t.Helper()
	response, err := client.Get(h.app.URL + "/whoami")
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var identity porte.Identity
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatalf("decoding the identity: %v", err)
	}
	return identity
}

func (h *harness) storedIdentity(t *testing.T) porte.StoredIdentity {
	t.Helper()
	h.stores.mu.Lock()
	defer h.stores.mu.Unlock()
	for _, identity := range h.stores.identities {
		return identity
	}
	t.Fatal("no identity was stored")
	return porte.StoredIdentity{}
}

func (h *harness) rewriteIdentity(change func(identity *porte.StoredIdentity)) {
	h.stores.mu.Lock()
	defer h.stores.mu.Unlock()
	for key, identity := range h.stores.identities {
		change(&identity)
		h.stores.identities[key] = identity
	}
}

func TestARevokedGrantDropsTheCachedRoles(t *testing.T) {
	h, client, gate := adminSession(t)
	gate.script(func(g *refreshGate) { g.refusal = "invalid_grant" })
	h.advance(porte.DefaultClaimsTTL + time.Second)

	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 0 {
		t.Fatalf("roles after the provider refused the grant = %v, want none", roles)
	}
	if stored := h.storedIdentity(t); len(stored.Roles) != 0 {
		t.Fatalf("the row still caches %v after the refusal", stored.Roles)
	}
	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 0 || gate.refreshes() != 1 {
		t.Fatalf("second request: roles = %v after %d refreshes, want none and no new attempt",
			roles, gate.refreshes())
	}
}

func TestARevokedRoleIsGoneWhileTheAccessTokenIsStillValid(t *testing.T) {
	h, client, gate := adminSession(t)
	if expiry := h.storedIdentity(t).Tokens.Expiry; !expiry.After(h.now().Add(porte.DefaultClaimsTTL * 2)) {
		t.Fatalf("the access token expires at %v, too soon for this test to prove anything", expiry)
	}
	gate.grant()
	h.advance(porte.DefaultClaimsTTL + time.Second)

	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 0 {
		t.Fatalf("roles after the last role was revoked = %v, want none", roles)
	}
	gate.grant("viewer")
	h.advance(porte.DefaultClaimsTTL + time.Second)
	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("roles after a new grant = %v, want viewer", roles)
	}
}

func TestAnIdentityWithNoRefreshTokenLosesItsRolesWhenTheyGoStale(t *testing.T) {
	h, client, gate := adminSession(t)
	h.rewriteIdentity(func(identity *porte.StoredIdentity) { identity.Tokens = porte.TokenSet{} })
	h.advance(porte.DefaultClaimsTTL + time.Second)

	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 0 {
		t.Fatalf("roles nothing can confirm any more = %v, want none", roles)
	}
	if gate.refreshes() != 0 || len(h.storedIdentity(t).Roles) != 0 {
		t.Fatalf("refreshes = %d, cached roles = %v; want no call and none cached",
			gate.refreshes(), h.storedIdentity(t).Roles)
	}
}

func TestAnOutageKeepsTheCachedRolesAndRetriesOneTTLLater(t *testing.T) {
	h, client, gate := adminSession(t)
	gate.script(func(g *refreshGate) { g.outage = true })
	h.advance(porte.DefaultClaimsTTL + time.Second)

	for range 2 {
		if roles := cookieIdentity(t, h, client).Roles; len(roles) != 1 || roles[0] != "admin" {
			t.Fatalf("roles during an outage = %v, want the cached admin", roles)
		}
	}
	if gate.refreshes() != 1 {
		t.Fatalf("%d refresh attempts during the outage, want one per ClaimsTTL", gate.refreshes())
	}
	gate.script(func(g *refreshGate) { g.outage = false })
	gate.grant("viewer")
	h.advance(porte.DefaultClaimsTTL + time.Second)
	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("roles once the provider is back = %v, want viewer", roles)
	}
}

func TestARefusalOfATokenAnotherReplicaRotatedKeepsTheRotatedRow(t *testing.T) {
	h, client, gate := adminSession(t)
	gate.script(func(g *refreshGate) {
		g.refusal = "invalid_grant"
		g.before = func() {
			h.rewriteIdentity(func(identity *porte.StoredIdentity) {
				identity.Tokens.RefreshToken = "rotated-elsewhere"
				identity.Roles = []string{"viewer"}
				identity.RolesSyncedAt = h.now()
			})
		}
	})
	h.advance(porte.DefaultClaimsTTL + time.Second)

	if roles := cookieIdentity(t, h, client).Roles; len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("roles = %v, want the row the other replica just wrote", roles)
	}
	if stored := h.storedIdentity(t); stored.Tokens.RefreshToken != "rotated-elsewhere" || len(stored.Roles) != 1 {
		t.Fatalf("the rotated row was overwritten: %+v", stored)
	}
}
