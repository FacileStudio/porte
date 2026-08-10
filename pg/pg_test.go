package pg_test

import (
	"context"
	"database/sql"
	stderrors "errors"
	"os"
	"strings"
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

// created_at answers "when did this credential appear on this account", which
// is the question an account-takeover audit asks. It is only an answer if the
// first write stamps it and no later write moves it — an upsert that carried it
// in EXCLUDED would reset the stamp on every login and the column would record
// the last sign-in instead.
func TestIdentityCreatedAtIsStampedOnceAndNeverMoves(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	userID, err := store.Users().UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	createdAt := func() time.Time {
		t.Helper()
		var at sql.NullTime
		if err := db.QueryRowContext(ctx,
			`SELECT created_at FROM porte_identities WHERE provider = $1 AND subject = $2`,
			"https://sso.test", "sub-1").Scan(&at); err != nil {
			t.Fatalf("read created_at: %v", err)
		}
		if !at.Valid {
			t.Fatal("created_at was not stamped")
		}
		return at.Time
	}

	first := createdAt()

	identities := store.Identities()
	if err := identities.Save(ctx, porte.StoredIdentity{
		UserID: userID, Provider: "https://sso.test", Subject: "sub-1",
		Tokens: porte.TokenSet{AccessToken: "at"},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true)); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	if again := createdAt(); !again.Equal(first) {
		t.Fatalf("created_at moved: %v then %v", first, again)
	}
}

// Applying the schema over a database created before created_at existed must
// add the column and leave the rows already there NULL. Filling them with the
// migration's own clock would date every identity in production to the deploy,
// which reads as an answer and is a fabrication — NULL says "predates the
// column", which is the truth and is what an audit needs to hear.
func TestCreatedAtDoesNotBackfillRowsThatPredateIt(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-1", "camille@facile.studio", true)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE porte_identities DROP COLUMN created_at`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if err := pg.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("re-apply schema: %v", err)
	}

	var at sql.NullTime
	if err := db.QueryRowContext(ctx,
		`SELECT created_at FROM porte_identities WHERE provider = $1 AND subject = $2`,
		"https://sso.test", "sub-1").Scan(&at); err != nil {
		t.Fatalf("read created_at: %v", err)
	}
	if at.Valid {
		t.Fatalf("an identity that predates the column was dated %v", at.Time)
	}

	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-2", "remy@facile.studio", true)); err != nil {
		t.Fatalf("upsert after migration: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT created_at FROM porte_identities WHERE provider = $1 AND subject = $2`,
		"https://sso.test", "sub-2").Scan(&at); err != nil {
		t.Fatalf("read created_at: %v", err)
	}
	if !at.Valid {
		t.Fatal("an identity created after the migration was not stamped")
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

	// Truncated to what timestamptz actually stores. Go's clock is
	// nanosecond on Linux, so an untruncated value comes back different
	// from what went in and the comparison below fails for a reason that
	// has nothing to do with what this test is about.
	now := time.Now().UTC().Truncate(time.Microsecond)
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

	// Raced rather than sequential: exactly-once is a claim about two
	// exchanges arriving at the same instant, which is the case a CLI retry
	// and an attacker replaying a captured code both produce. The single
	// conditional UPDATE is what settles it.
	const racers = 8
	won := make(chan porte.LoginCode, racers)
	lost := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			code, err := codes.Consume(ctx, "code-1")
			if err != nil {
				lost <- err
				return
			}
			won <- code
		}()
	}
	close(start)

	winners := 0
	for i := 0; i < racers; i++ {
		select {
		case code := <-won:
			winners++
			if code.UserID != userID {
				t.Fatalf("code = %+v", code)
			}
		case err := <-lost:
			if !stderrors.Is(err, porte.ErrCodeConsumed) {
				t.Fatalf("a losing exchange gave %v, want ErrCodeConsumed", err)
			}
		}
	}
	if winners != 1 {
		t.Fatalf("%d exchanges succeeded, want exactly 1", winners)
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

// A replayed code and a mistyped one both refuse the exchange, but only the
// first means somebody else is holding a credential. The contract pays for an
// error value to say so; before this the shipped store could not.
func TestAReplayedLoginCodeIsReportedAsAReplay(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	userID, err := store.Users().UpsertFromOIDC(ctx, claims("s1", "camille@example.test", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	codes := store.LoginCodes()
	if err := codes.Create(ctx, porte.LoginCode{
		CodeHash: "hash-1", UserID: userID, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := codes.Consume(ctx, "hash-1"); err != nil {
		t.Fatalf("the first exchange failed: %v", err)
	}
	if _, err := codes.Consume(ctx, "hash-1"); !stderrors.Is(err, porte.ErrCodeConsumed) {
		t.Fatalf("replaying a spent code returned %v, want ErrCodeConsumed", err)
	}
	if _, err := codes.Consume(ctx, "never-existed"); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("an unknown code returned %v, want ErrNotFound", err)
	}
}

// The spent rows kept to recognise a replay are swept on the same schedule as
// the unused ones, so nothing accumulates.
func TestTheSweeperTakesSpentCodesToo(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	userID, err := store.Users().UpsertFromOIDC(ctx, claims("s1", "camille@example.test", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	codes := store.LoginCodes()
	expired := time.Now().Add(-time.Minute)
	if err := codes.Create(ctx, porte.LoginCode{CodeHash: "spent", UserID: userID, ExpiresAt: expired}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := codes.Consume(ctx, "spent"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	deleted, err := codes.DeleteExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("swept %d rows, want the spent one gone", deleted)
	}
}

// The refresh-failure path records that it tried without writing back the
// identity it read before trying. Saving that whole row would roll a rotated
// refresh token back to the dead one, and every later refresh would fail.
func TestMarkRolesSyncedLeavesARotatedTokenAlone(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	identities := store.Identities()
	userID, err := store.Users().UpsertFromOIDC(ctx, claims("s1", "camille@example.test", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	stale := porte.StoredIdentity{
		UserID: userID, Provider: "https://sso.test", Subject: "s1",
		Tokens: porte.TokenSet{RefreshToken: "rotated-in-by-another-request"},
		Roles:  []string{"admin"},
	}
	if err := identities.Save(ctx, stale); err != nil {
		t.Fatalf("save: %v", err)
	}

	at := time.Now().Truncate(time.Millisecond)
	if err := identities.MarkRolesSynced(ctx, "https://sso.test", "s1", at); err != nil {
		t.Fatalf("mark: %v", err)
	}

	after, err := identities.Find(ctx, "https://sso.test", "s1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if after.Tokens.RefreshToken != "rotated-in-by-another-request" {
		t.Fatalf("the refresh token was clobbered: %q", after.Tokens.RefreshToken)
	}
	if len(after.Roles) != 1 || after.Roles[0] != "admin" {
		t.Fatalf("the cached roles were clobbered: %v", after.Roles)
	}
	if !after.RolesSyncedAt.Equal(at) {
		t.Fatalf("roles_synced_at = %v, want %v", after.RolesSyncedAt, at)
	}
}

func TestMarkRolesSyncedOnAnUnknownIdentityIsNotFound(t *testing.T) {
	store, _ := open(t)
	err := store.Identities().MarkRolesSynced(context.Background(), "https://sso.test", "nobody", time.Now())
	if !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// Two first logins for the same new user race in exactly one place: a double
// click, two tabs, or a callback the browser retried. Both pass the "does this
// email exist" read, and before the ON CONFLICT one of them died on the unique
// index with a 500 on the login path.
func TestConcurrentFirstLoginsResolveToOneUser(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	users := store.Users()

	const racers = 8
	ids := make(chan int64, racers)
	errs := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			id, err := users.UpsertFromOIDC(ctx, claims("s1", "camille@example.test", true))
			if err != nil {
				errs <- err
				return
			}
			ids <- id
		}()
	}
	close(start)

	seen := map[int64]bool{}
	for i := 0; i < racers; i++ {
		select {
		case err := <-errs:
			t.Fatalf("a concurrent first login failed: %v", err)
		case id := <-ids:
			seen[id] = true
		}
	}
	if len(seen) != 1 {
		t.Fatalf("the racers resolved to %d distinct users, want 1", len(seen))
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM porte_users`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("porte_users holds %d rows, want 1", count)
	}
}

// The conflict path must re-apply the guard it raced past. Two first logins
// with different subjects and the same email both find no row, and the loser
// arrives at the insert to find the email taken — adopting it there would be
// the account takeover the unverified-email rule exists to refuse.
func TestTheConflictPathStillRefusesAnUnverifiedEmail(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	users := store.Users()

	if _, err := users.UpsertFromOIDC(ctx, claims("s1", "shared@example.test", true)); err != nil {
		t.Fatalf("the first login failed: %v", err)
	}
	// A different subject, same address, and the provider will not vouch
	// for it. This is the takeover attempt.
	_, err := users.UpsertFromOIDC(ctx, claims("s2", "shared@example.test", false))
	if err == nil {
		t.Fatal("an unverified email was linked to an account it does not own")
	}
	if !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("err = %v, want the unverified-email refusal", err)
	}
}

// The password half of the store. A local account and a federated one are one
// user with two identity rows, so creating the first must not stop the second
// from finding it.
func TestPasswordUserStore(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	users := store.Users()

	if _, err := users.FindByEmail(ctx, "nobody@facile.studio"); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("FindByEmail on an unknown address = %v, want ErrNotFound", err)
	}

	userID, err := users.CreateFromPassword(ctx, "camille@facile.studio", "Camille")
	if err != nil {
		t.Fatalf("CreateFromPassword: %v", err)
	}
	found, err := users.FindByEmail(ctx, "camille@facile.studio")
	if err != nil || found != userID {
		t.Fatalf("FindByEmail = %d, %v; want %d", found, err, userID)
	}

	// The unique index is what actually stops a duplicate, since the app
	// holds the lock rather than this store.
	if _, err := users.CreateFromPassword(ctx, "camille@facile.studio", "Camille"); err == nil {
		t.Fatal("a duplicate address was created")
	}

	// A password identity and an OIDC one on the same human, which is the
	// arrangement v0.2 exists to allow.
	identities := store.Identities()
	for _, identity := range []porte.StoredIdentity{
		{UserID: userID, Provider: porte.ProviderLocal, Subject: "camille@facile.studio", PasswordHash: "$argon2id$fake"},
		{UserID: userID, Provider: "https://sso.test/", Subject: "abc"},
	} {
		if err := identities.Save(ctx, identity); err != nil {
			t.Fatalf("save %s: %v", identity.Provider, err)
		}
	}
	held, err := identities.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("expected two identities on one human, got %d", len(held))
	}

	local, err := identities.Find(ctx, porte.ProviderLocal, "camille@facile.studio")
	if err != nil {
		t.Fatalf("find the local identity: %v", err)
	}
	if local.PasswordHash != "$argon2id$fake" {
		t.Fatalf("the password hash did not round trip: %q", local.PasswordHash)
	}
}

// The v0.3.0 migration, which is the only statement in Schema that touches
// existing credential rows. It runs on every boot, so it has to be idempotent
// as well as correct, and it has to leave federated identities alone — their
// subject is the IdP's and moving it would unlink every SSO account at once.
func TestSchemaRekeysLocalIdentitiesOntoTheAccountID(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()

	userID, err := store.Users().UpsertFromOIDC(ctx, claims("sso-subject", "camille@facile.studio", true))
	if err != nil {
		t.Fatalf("seed the user: %v", err)
	}
	if err := store.Identities().Save(ctx, porte.StoredIdentity{
		UserID: userID, Provider: porte.ProviderLocal,
		Subject: "camille@facile.studio", PasswordHash: "argon2-hash",
	}); err != nil {
		t.Fatalf("seed a v0.2 email-keyed identity: %v", err)
	}
	if err := store.Identities().Save(ctx, porte.StoredIdentity{
		UserID: userID, Provider: "https://sso.test", Subject: "sso-subject",
	}); err != nil {
		t.Fatalf("seed the federated identity: %v", err)
	}

	for attempt := range 2 {
		if err := pg.EnsureSchema(ctx, db); err != nil {
			t.Fatalf("migration run %d: %v", attempt+1, err)
		}

		moved, err := store.Identities().Find(ctx, porte.ProviderLocal, porte.LocalSubject(userID))
		if err != nil {
			t.Fatalf("run %d: the password is not keyed on the account id: %v", attempt+1, err)
		}
		if moved.PasswordHash != "argon2-hash" {
			t.Fatalf("run %d: the migration lost the hash: %q", attempt+1, moved.PasswordHash)
		}
		if _, err := store.Identities().Find(ctx, porte.ProviderLocal, "camille@facile.studio"); !stderrors.Is(err, porte.ErrNotFound) {
			t.Fatalf("run %d: the address is still a credential key: %v", attempt+1, err)
		}
		if _, err := store.Identities().Find(ctx, "https://sso.test", "sso-subject"); err != nil {
			t.Fatalf("run %d: the migration moved a federated subject: %v", attempt+1, err)
		}
	}
}
