package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/FacileStudio/porte"
	jwtpkg "github.com/FacileStudio/porte/oidc/jwt"
)

// stubTokens stands in for the signature half of the bearer path, so the
// resolution half can be driven through every claim shape without minting a
// signed token for each one. lookups counts what reached the identity store,
// which is how the ordering assertions below are made.
type stubTokens struct {
	claims jwtpkg.Claims
	err    error
}

func (s stubTokens) Verify(context.Context, string) (jwtpkg.Claims, error) {
	return s.claims, s.err
}

// countingIdentities wraps an identity store and records how many lookups it
// was asked for.
type countingIdentities struct {
	porte.IdentityStore
	lookups int
}

func (c *countingIdentities) Find(ctx context.Context, provider, subject string) (porte.StoredIdentity, error) {
	c.lookups++
	return c.IdentityStore.Find(ctx, provider, subject)
}

const testIssuer = "https://sso.facile.studio"

func bearerFixture(t *testing.T, claims jwtpkg.Claims, err error) (bearerVerifier, *countingIdentities, *flowStores) {
	t.Helper()
	stores := newFlowStores()
	identities := &countingIdentities{IdentityStore: identityStore{stores}}
	return bearerVerifier{
		tokens:     stubTokens{claims: claims, err: err},
		identities: identities,
		issuer:     testIssuer,
	}, identities, stores
}

func saveIdentity(t *testing.T, stores *flowStores, issuer, subject string, userID int64) {
	t.Helper()
	err := identityStore{stores}.Save(context.Background(), porte.StoredIdentity{
		UserID:   userID,
		Provider: issuer,
		Subject:  subject,
	})
	if err != nil {
		t.Fatalf("seeding the identity: %v", err)
	}
}

// TestABearerJWTResolvesToTheLocalAccount is the point of the change: a token
// the issuer signed for this app authenticates as the human it names, matched
// on (issuer, sub) in porte_identities exactly as the login callback matches.
func TestABearerJWTResolvesToTheLocalAccount(t *testing.T) {
	verifier, _, stores := bearerFixture(t, jwtpkg.Claims{
		Subject: "registre-uuid-1",
		Email:   "yann@facile.studio",
		Name:    "Yann",
		Roles:   []string{"admin"},
	}, nil)
	saveIdentity(t, stores, testIssuer, "registre-uuid-1", 42)

	identity, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here")
	if err != nil {
		t.Fatalf("a valid token for a known subject was refused: %v", err)
	}
	if identity.UserID != 42 {
		t.Errorf("UserID = %d, want 42 — the token must resolve to the local account", identity.UserID)
	}
	if identity.Subject != "registre-uuid-1" {
		t.Errorf("Subject = %q", identity.Subject)
	}
	if !identity.HasRole("admin") {
		t.Errorf("Roles = %v, want the roles the verified token asserted", identity.Roles)
	}
}

// TestRolesComeFromTheVerifiedTokenNotTheCachedRow pins which of the two
// answers wins. The row caches what the provider last said during a browser
// login; the token carries what it says now, signed and already filtered for
// this client, so the token wins. The consequence is deliberate and worth
// knowing: a provider that emits no roles claim on an access token leaves a
// bearer caller with no roles at all rather than with yesterday's, which
// fails closed on authorization instead of open.
func TestRolesComeFromTheVerifiedTokenNotTheCachedRow(t *testing.T) {
	verifier, _, stores := bearerFixture(t, jwtpkg.Claims{
		Subject: "registre-uuid-1",
		Roles:   []string{"admin"},
	}, nil)
	saveIdentity(t, stores, testIssuer, "registre-uuid-1", 42)
	stores.mu.Lock()
	key := testIssuer + "\x00" + "registre-uuid-1"
	stale := stores.identities[key]
	stale.Roles = []string{"viewer"}
	stores.identities[key] = stale
	stores.mu.Unlock()

	identity, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !identity.HasRole("admin") || identity.HasRole("viewer") {
		t.Errorf("Roles = %v, want the token's claim rather than the cached row", identity.Roles)
	}
}

// TestASubjectWithNoLocalIdentityIsRefused pins the fail-closed half. A
// perfectly good suite token for somebody who has never signed in here is not
// an account, and porte does not provision one from a bearer: the callback
// owns account creation because it is the path holding a verified email.
func TestASubjectWithNoLocalIdentityIsRefused(t *testing.T) {
	verifier, _, _ := bearerFixture(t, jwtpkg.Claims{Subject: "stranger"}, nil)

	if _, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here"); err == nil {
		t.Fatal("a subject with no row in porte_identities authenticated")
	}
}

// TestADeactivatedAccountIsRefusedOnTheBearerPath is the failure this change
// most needed not to ship. Revoking sessions is all back-channel logout can
// do and a JWT has no session row, so the identity lookup is the only thing
// standing between a deactivated employee and a token that has not expired
// yet. An app deactivates by making Find refuse; this asserts the refusal
// reaches the middleware rather than being swallowed into an empty identity.
func TestADeactivatedAccountIsRefusedOnTheBearerPath(t *testing.T) {
	verifier, _, stores := bearerFixture(t, jwtpkg.Claims{Subject: "registre-uuid-1"}, nil)
	saveIdentity(t, stores, testIssuer, "registre-uuid-1", 42)

	if _, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here"); err != nil {
		t.Fatalf("the account should authenticate while it is live: %v", err)
	}

	stores.mu.Lock()
	delete(stores.identities, testIssuer+"\x00"+"registre-uuid-1")
	stores.mu.Unlock()

	identity, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here")
	if err == nil {
		t.Fatalf("a deactivated account still authenticated as %+v", identity)
	}
	if identity.UserID != 0 {
		t.Errorf("a refusal handed back UserID %d", identity.UserID)
	}
}

// TestATokenWithNoSubjectIsRefused stops an empty sub from resolving to
// whatever an identity store answers for the empty string.
func TestATokenWithNoSubjectIsRefused(t *testing.T) {
	verifier, identities, stores := bearerFixture(t, jwtpkg.Claims{Email: "yann@facile.studio"}, nil)
	saveIdentity(t, stores, testIssuer, "", 42)

	if _, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here"); err == nil {
		t.Fatal("a token asserting no subject authenticated")
	}
	if identities.lookups != 0 {
		t.Errorf("an empty subject reached the store %d times", identities.lookups)
	}
}

// TestAnUnverifiedTokenNeverReachesTheIdentityStore is the timing property. A
// caller who cannot produce a signature the issuer made is refused at the same
// cost whoever they claim to be, because the store is only consulted once the
// signature and the registered claims have already passed. Without this the
// refusal time would answer "does this subject have an account here" to
// anybody who can send a request.
func TestAnUnverifiedTokenNeverReachesTheIdentityStore(t *testing.T) {
	verifier, identities, stores := bearerFixture(t, jwtpkg.Claims{Subject: "registre-uuid-1"}, errors.New("bad signature"))
	saveIdentity(t, stores, testIssuer, "registre-uuid-1", 42)

	if _, err := verifier.VerifyJWT(context.Background(), "signed.jwt.here"); err == nil {
		t.Fatal("a token that failed verification authenticated")
	}
	if identities.lookups != 0 {
		t.Errorf("a refused token cost %d identity lookups; a refusal must not vary with local state", identities.lookups)
	}
}
