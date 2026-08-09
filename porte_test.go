package porte_test

import (
	"context"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

func TestConfigValidateNamesEveryMissingVariable(t *testing.T) {
	if err := (porte.Config{}).Validate(); err != nil {
		t.Fatalf("an unconfigured Config must be valid, got %v", err)
	}

	err := porte.Config{Issuer: "https://sso.facile.studio/application/o/nuage/"}.Validate()
	if err == nil {
		t.Fatal("an issuer with no client credentials must not validate")
	}
	for _, name := range []string{"OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "OIDC_SUCCESS_URL"} {
		if !contains(err.Error(), name) {
			t.Errorf("error must name %s, got %q", name, err)
		}
	}
}

// url.Parse accepts almost any string, so testing its error catches nothing:
// a bare hostname parses fine as a relative path and then fails discovery at
// boot with a message naming neither the variable nor the problem.
func TestConfigValidateRejectsAnIssuerThatIsNotAnAbsoluteURL(t *testing.T) {
	for _, issuer := range []string{"sso.facile.studio", "/application/o/nuage/", "ftp://sso.test", "https://"} {
		err := porte.Config{
			Issuer:       issuer,
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "https://app.test/auth/oidc/callback",
			SuccessURL:   "https://app.test/",
		}.Validate()
		if err == nil {
			t.Errorf("issuer %q was accepted", issuer)
		}
	}
}

// Every app stores session hashes as hex SHA-256 today. Changing the encoding
// would log out the entire suite on the commit that adopts porte.
func TestHashTokenKeepsTheEncodingTheAppsAlreadyStore(t *testing.T) {
	got := porte.HashToken("hello")
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Fatalf("HashToken = %q, want %q", got, want)
	}
	if porte.HashToken("a") == porte.HashToken("b") {
		t.Fatal("distinct tokens hashed the same")
	}
}

func TestNewTokenIsUnpredictableAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		token, err := porte.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if seen[token] {
			t.Fatal("NewToken repeated itself")
		}
		seen[token] = true
		if len(token) < 40 {
			t.Fatalf("token is only %d characters", len(token))
		}
		if contains(token, "+") || contains(token, "/") || contains(token, "=") {
			t.Fatalf("token %q needs escaping in a cookie or a URL", token)
		}
	}
}

func TestSecureCompare(t *testing.T) {
	if !porte.SecureCompare("abc", "abc") {
		t.Fatal("equal values compared unequal")
	}
	if porte.SecureCompare("abc", "abd") || porte.SecureCompare("abc", "ab") || porte.SecureCompare("", "x") {
		t.Fatal("unequal values compared equal")
	}
}

func TestScopesCarryClaimsOnlyWhenConfigured(t *testing.T) {
	base := porte.Config{Issuer: "https://sso.facile.studio/"}
	if got := len(base.Scopes()); got != 4 {
		t.Fatalf("default scopes = %d, want the 4 every app already requests", got)
	}
	if base.ClaimsEnabled() {
		t.Fatal("claims must be off unless a scope is configured")
	}

	withClaims := base
	withClaims.ClaimsScope = "facile_roles"
	scopes := withClaims.Scopes()
	if len(scopes) != 5 || scopes[4] != "facile_roles" {
		t.Fatalf("claims scope must be appended, got %v", scopes)
	}
}

func TestResolvedFillsZeroDurations(t *testing.T) {
	resolved := porte.Config{}.Resolved()
	if resolved.SessionTTL != porte.DefaultSessionTTL ||
		resolved.ClaimsTTL != porte.DefaultClaimsTTL ||
		resolved.LoginCodeTTL != porte.DefaultLoginCodeTTL {
		t.Fatalf("zero durations must fall back to defaults, got %+v", resolved)
	}

	explicit := porte.Config{SessionTTL: time.Hour}.Resolved()
	if explicit.SessionTTL != time.Hour {
		t.Fatalf("an explicit TTL must survive Resolved, got %v", explicit.SessionTTL)
	}
}

func TestLoginFailureLandsOnTheLoginPageWithTheReason(t *testing.T) {
	// SuccessURL is a landing page, not the origin: appending would send a
	// refused login to /dashboard/login, which is nowhere.
	cfg := porte.Config{SuccessURL: "https://app.test/dashboard"}
	got := cfg.LoginFailure("email not verified")
	if got != "https://app.test/login?error=email+not+verified" {
		t.Fatalf("LoginFailure = %q, want /login on the same origin carrying the reason", got)
	}

	override := porte.Config{SuccessURL: "https://app.test/", FailureURL: "https://app.test/sign-in?from=sso"}
	got = override.LoginFailure("nope")
	if got != "https://app.test/sign-in?error=nope&from=sso" {
		t.Fatalf("LoginFailure with FailureURL = %q, want the configured page with its query kept", got)
	}
}

func TestDisplayNamePrecedence(t *testing.T) {
	cases := []struct {
		name   string
		claims porte.Claims
		want   string
	}{
		{"name wins", porte.Claims{Name: "Sara", PreferredUsername: "saravenpi", GivenName: "S"}, "Sara"},
		{"then preferred_username", porte.Claims{PreferredUsername: "saravenpi", GivenName: "S"}, "saravenpi"},
		{"then given and family", porte.Claims{GivenName: "Sara", FamilyName: "V"}, "Sara V"},
		{"family alone is not padded", porte.Claims{FamilyName: "V"}, "V"},
		{"nothing asserted", porte.Claims{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.DisplayName(); got != tc.want {
				t.Fatalf("DisplayName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIdentityRolesAreExactMatches(t *testing.T) {
	id := porte.Identity{Roles: []string{"admin", "billing"}}
	if !id.HasRole("admin") || !id.HasAnyRole("nope", "billing") {
		t.Fatal("a granted role must match")
	}
	if id.HasRole("Admin") || id.HasRole("admins") || id.HasRole("") {
		t.Fatal("role matching must be exact — the claim is already scoped per application")
	}
	if (porte.Identity{}).HasAnyRole("admin") {
		t.Fatal("an identity with no roles grants nothing")
	}
}

func TestSessionExpiryTreatsZeroAsNever(t *testing.T) {
	now := time.Now()
	if (porte.Session{}).Expired(now) {
		t.Fatal("a zero ExpiresAt is an API token and never expires")
	}
	if (porte.Session{ExpiresAt: now.Add(time.Minute)}).Expired(now) {
		t.Fatal("a future expiry is not expired")
	}
	if !(porte.Session{ExpiresAt: now.Add(-time.Minute)}).Expired(now) {
		t.Fatal("a past expiry is expired")
	}
}

func TestRolesStaleWhenNeverSynced(t *testing.T) {
	now := time.Now()
	if !(porte.StoredIdentity{}).RolesStale(now, time.Minute) {
		t.Fatal("claims that were never synced are stale — a missing refresh must not read as fresh")
	}
	fresh := porte.StoredIdentity{RolesSyncedAt: now.Add(-30 * time.Second)}
	if fresh.RolesStale(now, time.Minute) {
		t.Fatal("claims within the TTL are fresh")
	}
}

func TestIdentityRoundTripsThroughContext(t *testing.T) {
	if _, ok := porte.From(context.Background()); ok {
		t.Fatal("a bare context must not carry an identity")
	}
	ctx := porte.WithIdentity(context.Background(), porte.Identity{UserID: 7, Email: "saravenpi@tuta.io"})
	id, ok := porte.From(ctx)
	if !ok || id.UserID != 7 {
		t.Fatalf("From() = %+v, %v", id, ok)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
