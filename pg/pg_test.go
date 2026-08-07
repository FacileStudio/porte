package pg_test

import (
	"context"
	"database/sql"
	stderrors "errors"
	"os"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// open returns a store over a real PostgreSQL, or skips.
//
// It skips rather than faking, because every interesting behaviour in this
// package is PostgreSQL's: DELETE ... RETURNING settling a race, ON CONFLICT
// resolving an upsert, a unique index refusing a duplicate. A fake would test
// the fake. CI runs a postgres:16 service so the skip never fires there.
func open(t *testing.T) (*pg.Store, *sql.DB) {
	t.Helper()
	url := os.Getenv("PORTE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PORTE_TEST_DATABASE_URL is unset")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := pg.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, table := range []string{"porte_login_codes", "porte_sessions", "porte_identities", "porte_users"} {
		if _, err := db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("clean %s: %v", table, err)
		}
	}
	return pg.New(db), db
}

func claims(subject, email string, verified bool) porte.Claims {
	return porte.Claims{
		Provider:      "https://sso.test",
		Subject:       subject,
		Email:         email,
		EmailVerified: verified,
		Name:          "Camille",
	}
}

func TestUpsertMatchesOnSubjectNotEmail(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	users := store.Users()

	first, err := users.UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// The IdP renamed the account. Matching on the subject keeps it the
	// same human; matching on email would have orphaned it.
	again, err := users.UpsertFromOIDC(ctx, claims("sub-1", "camille.b@facile.studio", true))
	if err != nil {
		t.Fatalf("renamed upsert: %v", err)
	}
	if again != first {
		t.Fatalf("a renamed email forked the account: %d then %d", first, again)
	}
}

func TestUpsertLinksAnExistingEmailOnlyWhenTheProviderVerifiedIt(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	users := store.Users()

	original, err := users.UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// A different subject claiming the same address, unverified. Linking
	// here is an account takeover primitive, so it must not link — and it
	// must fail with something legible rather than a constraint violation.
	if _, err := users.UpsertFromOIDC(ctx, claims("sub-2", "camille@facile.studio", false)); err == nil {
		t.Fatal("an unverified email was allowed to reach an existing account")
	}

	// Verified, so the link is taken: this is the case of an account that
	// predates oidc_subject being recorded.
	linked, err := users.UpsertFromOIDC(ctx, claims("sub-3", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("verified link: %v", err)
	}
	if linked != original {
		t.Fatalf("a verified email did not link: %d vs %d", linked, original)
	}
}

func TestIdentityRoundTripsIncludingRoles(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	userID, err := store.Users().UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	identities := store.Identities()
	now := time.Now().UTC().Truncate(time.Millisecond)
	want := porte.StoredIdentity{
		UserID:        userID,
		Provider:      "https://sso.test",
		Subject:       "sub-1",
		Tokens:        porte.TokenSet{AccessToken: "at", RefreshToken: "rt", Expiry: now},
		Roles:         []string{"admin", "billing"},
		RolesSyncedAt: now,
		SyncedAt:      now,
	}
	if err := identities.Save(ctx, want); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := identities.Find(ctx, want.Provider, want.Subject)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "admin" || got.Roles[1] != "billing" {
		t.Fatalf("roles = %v", got.Roles)
	}
	if got.Tokens.AccessToken != "at" || got.Tokens.RefreshToken != "rt" {
		t.Fatalf("tokens = %+v", got.Tokens)
	}
	if !got.Tokens.Expiry.Equal(now) || !got.RolesSyncedAt.Equal(now) {
		t.Fatalf("timestamps did not survive: %+v", got)
	}

	if _, err := identities.Find(ctx, "https://sso.test", "nobody"); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("missing identity gave %v, want ErrNotFound", err)
	}
}

// A stamp that was never set must read back as zero, not as the year 1: the
// whole freshness model keys on IsZero meaning "never refreshed".
func TestUnsetStampsReadBackAsZero(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	userID, err := store.Users().UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	identities := store.Identities()
	if err := identities.Save(ctx, porte.StoredIdentity{
		UserID: userID, Provider: "https://sso.test", Subject: "sub-1",
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := identities.Find(ctx, "https://sso.test", "sub-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if !got.RolesSyncedAt.IsZero() || !got.SyncedAt.IsZero() || !got.Tokens.Expiry.IsZero() {
		t.Fatalf("an unset stamp came back non-zero: %+v", got)
	}
	if !got.RolesStale(time.Now(), time.Minute) {
		t.Fatal("a never-synced identity was reported fresh")
	}
}

func TestSessionLifecycle(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	sessions := store.Sessions()
	userID := seedUser(t, store, "sub-1", "camille@facile.studio")

	now := time.Now().UTC()
	created, err := sessions.Create(ctx, porte.Session{
		TokenHash: "hash-1", UserID: userID,
		CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("create returned no id")
	}

	found, err := sessions.Find(ctx, "hash-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if found.ID != created.ID || found.UserID != userID {
		t.Fatalf("found = %+v", found)
	}
	if _, err := sessions.Find(ctx, "nope"); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("missing session gave %v, want ErrNotFound", err)
	}

	// Revoking by id is scoped to the owner, so guessing an integer gets
	// you nothing.
	if err := sessions.DeleteByID(ctx, userID+1000, created.ID); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("another user revoked the session (%v)", err)
	}
	if err := sessions.DeleteByID(ctx, userID, created.ID); err != nil {
		t.Fatalf("owner could not revoke: %v", err)
	}
	if _, err := sessions.Find(ctx, "hash-1"); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("the session survived revocation (%v)", err)
	}
}

// An API token has no expiry. The sweeper must leave it alone, or every named
// token in the suite disappears the first time the sweeper runs.
func TestSweeperSparesSessionsWithoutAnExpiry(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	sessions := store.Sessions()
	userID := seedUser(t, store, "sub-1", "camille@facile.studio")

	now := time.Now().UTC()
	mustCreate(t, sessions, porte.Session{TokenHash: "expired", UserID: userID, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(-time.Hour)})
	mustCreate(t, sessions, porte.Session{TokenHash: "live", UserID: userID, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)})
	mustCreate(t, sessions, porte.Session{TokenHash: "api-token", UserID: userID, Label: "ci", CreatedAt: now, LastUsedAt: now})

	deleted, err := sessions.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("swept %d rows, want 1", deleted)
	}
	token, err := sessions.Find(ctx, "api-token")
	if err != nil {
		t.Fatalf("the API token was swept: %v", err)
	}
	if !token.IsAPIToken() || token.Expired(now.Add(10*365*24*time.Hour)) {
		t.Fatalf("an unexpiring token did not survive: %+v", token)
	}
}

func TestTouchDoesNotWriteInsideTheInterval(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	sessions := store.Sessions()
	userID := seedUser(t, store, "sub-1", "camille@facile.studio")

	now := time.Now().UTC()
	mustCreate(t, sessions, porte.Session{TokenHash: "hash-1", UserID: userID, CreatedAt: now, LastUsedAt: now})

	if err := sessions.Touch(ctx, "hash-1", now.Add(30*time.Second)); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if got := lastUsed(t, db, "hash-1"); !got.Equal(now) {
		t.Fatalf("last_used_at moved inside the interval: %v", got)
	}

	later := now.Add(2 * time.Minute)
	if err := sessions.Touch(ctx, "hash-1", later); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if got := lastUsed(t, db, "hash-1"); !got.Equal(later) {
		t.Fatalf("last_used_at = %v, want %v", got, later)
	}
}

func TestBackchannelLogoutRevokesEverySessionOfAUser(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	sessions := store.Sessions()
	mine := seedUser(t, store, "sub-1", "camille@facile.studio")
	theirs := seedUser(t, store, "sub-2", "remi@facile.studio")

	now := time.Now().UTC()
	mustCreate(t, sessions, porte.Session{TokenHash: "a", UserID: mine, CreatedAt: now, LastUsedAt: now})
	mustCreate(t, sessions, porte.Session{TokenHash: "b", UserID: mine, CreatedAt: now, LastUsedAt: now})
	mustCreate(t, sessions, porte.Session{TokenHash: "c", UserID: theirs, CreatedAt: now, LastUsedAt: now})

	deleted, err := sessions.DeleteByUser(ctx, mine)
	if err != nil {
		t.Fatalf("delete by user: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("revoked %d sessions, want 2", deleted)
	}
	if _, err := sessions.Find(ctx, "c"); err != nil {
		t.Fatalf("someone else's session was revoked: %v", err)
	}
}

func TestALoginCodeIsConsumedExactlyOnce(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	codes := store.LoginCodes()
	userID := seedUser(t, store, "sub-1", "camille@facile.studio")

	expiry := time.Now().UTC().Add(time.Minute)
	if err := codes.Create(ctx, porte.LoginCode{CodeHash: "code-1", UserID: userID, ExpiresAt: expiry}); err != nil {
		t.Fatalf("create: %v", err)
	}

	code, err := codes.Consume(ctx, "code-1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if code.UserID != userID {
		t.Fatalf("code = %+v", code)
	}
	if _, err := codes.Consume(ctx, "code-1"); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("a replayed code gave %v, want ErrNotFound", err)
	}
}

func seedUser(t *testing.T, store *pg.Store, subject, email string) int64 {
	t.Helper()
	userID, err := store.Users().UpsertFromOIDC(context.Background(), claims(subject, email, true))
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return userID
}

func mustCreate(t *testing.T, sessions *pg.SessionStore, session porte.Session) {
	t.Helper()
	if _, err := sessions.Create(context.Background(), session); err != nil {
		t.Fatalf("create session %s: %v", session.TokenHash, err)
	}
}

func lastUsed(t *testing.T, db *sql.DB, tokenHash string) time.Time {
	t.Helper()
	var at time.Time
	if err := db.QueryRow(`SELECT last_used_at FROM porte_sessions WHERE token_hash = $1`, tokenHash).Scan(&at); err != nil {
		t.Fatalf("read last_used_at: %v", err)
	}
	return at.UTC()
}
