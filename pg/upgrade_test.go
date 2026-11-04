package pg_test

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
)

// oldDDL is the shape thirteen adopters run: their accounts in their own
// `users` table, no porte_users at all, and porte's tables at their v0.9.0
// columns, referencing users.
const oldDDL = `
DROP SCHEMA IF EXISTS porte_old CASCADE;
CREATE SCHEMA porte_old;
CREATE TABLE porte_old.users (id bigserial PRIMARY KEY, email text NOT NULL UNIQUE);
CREATE TABLE porte_old.porte_identities (
	user_id bigint NOT NULL REFERENCES porte_old.users(id) ON DELETE CASCADE,
	provider text NOT NULL, subject text NOT NULL, password_hash text NOT NULL DEFAULT '',
	access_token text NOT NULL DEFAULT '', refresh_token text NOT NULL DEFAULT '',
	token_expiry timestamptz, roles jsonb, roles_synced_at timestamptz, synced_at timestamptz,
	created_at timestamptz DEFAULT now(), PRIMARY KEY (provider, subject));
CREATE TABLE porte_old.porte_sessions (
	id bigserial PRIMARY KEY, token_hash text NOT NULL UNIQUE,
	user_id bigint NOT NULL REFERENCES porte_old.users(id) ON DELETE CASCADE,
	label text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
	last_used_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz);
CREATE TABLE porte_old.porte_login_codes (
	code_hash text PRIMARY KEY,
	user_id bigint NOT NULL REFERENCES porte_old.users(id) ON DELETE CASCADE,
	expires_at timestamptz NOT NULL, consumed_at timestamptz);
`

// codeColumns is checklist item 5's migration for these apps.
const codeColumns = `ALTER TABLE porte_login_codes ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS subject text NOT NULL DEFAULT ''`

// openOldDDL is a store over that shape, through a pool whose search_path
// finds it first, so porte_users is nowhere to be seen.
func openOldDDL(t *testing.T) (*pg.Store, *sql.DB) {
	t.Helper()
	_, admin := open(t)
	if _, err := admin.ExecContext(context.Background(), oldDDL); err != nil {
		t.Fatalf("old DDL: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS porte_old CASCADE`) })
	url := os.Getenv("PORTE_TEST_DATABASE_URL")
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	db, err := sql.Open("pgx", url+separator+"search_path=porte_old")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return pg.New(db), db
}

// appFirstLogin is what such an app's own UpsertFromOIDC does: its own user
// row, then porte's identity through Save.
func appFirstLogin(t *testing.T, store *pg.Store, db *sql.DB, email, subject string) int64 {
	t.Helper()
	var userID int64
	if err := db.QueryRowContext(context.Background(), `INSERT INTO users (email) VALUES ($1) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("user: %v", err)
	}
	if err := store.Identities().Save(context.Background(), porte.StoredIdentity{UserID: userID, Provider: "https://sso.test", Subject: subject}); err != nil {
		t.Fatalf("first-login Save without porte_users: %v", err)
	}
	return userID
}

// TestAnAppWithItsOwnUsersTableSignsInThroughEveryFlow: no porte_users, old
// columns. The browser flow and password and API sessions work as is; the CLI
// and mobile flows work once the item 5 columns exist.
func TestAnAppWithItsOwnUsersTableSignsInThroughEveryFlow(t *testing.T) {
	store, db := openOldDDL(t)
	ctx := context.Background()
	userID := appFirstLogin(t, store, db, "old@example.test", "old-sub")
	bound := porte.Session{UserID: userID, Provider: "https://sso.test", Subject: "old-sub", CreatedAt: time.Now(), LastUsedAt: time.Now()}
	browser := bound
	browser.TokenHash = "browser"
	if _, err := store.Sessions().Create(ctx, browser); err != nil {
		t.Fatalf("browser login session: %v", err)
	}
	unbound := porte.Session{UserID: userID, TokenHash: "unbound", CreatedAt: time.Now(), LastUsedAt: time.Now()}
	if _, err := store.Sessions().Create(ctx, unbound); err != nil {
		t.Fatalf("unbound session: %v", err)
	}
	if _, err := db.ExecContext(ctx, codeColumns); err != nil {
		t.Fatalf("item 5 migration: %v", err)
	}
	for _, hash := range []string{"cli-code", "mobile-code:challenge"} {
		exchangeCode(t, store, bound, hash)
	}
}

// exchangeCode runs the CLI or mobile tail of a login: a bound code, its
// redemption, and the bound session the exchange mints from it.
func exchangeCode(t *testing.T, store *pg.Store, bound porte.Session, hash string) {
	t.Helper()
	ctx := context.Background()
	code := porte.LoginCode{CodeHash: hash, UserID: bound.UserID, ExpiresAt: time.Now().Add(time.Minute), Provider: bound.Provider, Subject: bound.Subject}
	if err := store.LoginCodes().Create(ctx, code); err != nil {
		t.Fatalf("%s: %v", hash, err)
	}
	redeemed, err := store.LoginCodes().Consume(ctx, hash)
	if err != nil || redeemed.Provider != bound.Provider || redeemed.Subject != bound.Subject {
		t.Fatalf("consume %s = %+v, %v", hash, redeemed, err)
	}
	exchanged := porte.Session{UserID: redeemed.UserID, Provider: redeemed.Provider, Subject: redeemed.Subject,
		TokenHash: "session-" + hash, CreatedAt: time.Now(), LastUsedAt: time.Now()}
	if _, err := store.Sessions().Create(ctx, exchanged); err != nil {
		t.Fatalf("exchange %s: %v", hash, err)
	}
}

// TestAnUnboundCodeWorksOnTheOldColumns: before item 5, a code nobody bound
// still round-trips.
func TestAnUnboundCodeWorksOnTheOldColumns(t *testing.T) {
	store, db := openOldDDL(t)
	ctx := context.Background()
	userID := appFirstLogin(t, store, db, "plain@example.test", "plain-sub")
	if err := store.LoginCodes().Create(ctx, porte.LoginCode{CodeHash: "plain", UserID: userID, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("unbound code: %v", err)
	}
	if got, err := store.LoginCodes().Consume(ctx, "plain"); err != nil || got.UserID != userID || got.Provider != "" {
		t.Fatalf("consume = %+v, %v", got, err)
	}
}

// TestAnAppOwnedUpsertCreatesItsIdentityThroughSave: thirteen adopters link
// the first login with Save, so Save must still insert an absent identity.
func TestAnAppOwnedUpsertCreatesItsIdentityThroughSave(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	userID, err := store.Users().CreateFromPassword(ctx, "appuser@example.test", "A")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Identities().Save(ctx, porte.StoredIdentity{UserID: userID, Provider: "https://sso.test", Subject: "app-sub"}); err != nil {
		t.Fatalf("first-login Save: %v", err)
	}
	if got, err := store.Identities().Find(ctx, "https://sso.test", "app-sub"); err != nil || got.UserID != userID {
		t.Fatalf("Find = %+v, %v", got, err)
	}
	refreshed := porte.StoredIdentity{UserID: userID, Provider: "https://sso.test", Subject: "app-sub", Tokens: porte.TokenSet{AccessToken: "fresh"}}
	if err := store.Identities().Save(ctx, refreshed); err != nil {
		t.Fatalf("refresh Save: %v", err)
	}
}

// TestSaveNeverRepointsAnIdentity: a Save naming another account changes
// nothing and says so.
func TestSaveNeverRepointsAnIdentity(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	a, errA := store.Users().UpsertFromOIDC(ctx, claims("sub-a", "a@example.test", true))
	b, errB := store.Users().UpsertFromOIDC(ctx, claims("sub-b", "b@example.test", true))
	if errA != nil || errB != nil {
		t.Fatalf("logins: %v %v", errA, errB)
	}
	err := store.Identities().Save(ctx, porte.StoredIdentity{UserID: b, Provider: "https://sso.test", Subject: "sub-a"})
	got, _ := store.Identities().Find(ctx, "https://sso.test", "sub-a")
	if got.UserID != a || !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("Save re-pointed sub-a: err %v, owner %d (want %d)", err, got.UserID, a)
	}
}

// TestPurgeAndBoundSessionRaceFreely runs the eviction and the squatter's
// bound session insert at once, many times. The squatter's session never
// survives on the owner's account.
func TestPurgeAndBoundSessionRaceFreely(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	for i := range 40 {
		email := fmt.Sprintf("race%d@example.test", i)
		squatter, err := store.Users().UpsertFromOIDC(ctx, claims("att"+email, email, false))
		if err != nil {
			t.Fatalf("squat %d: %v", i, err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = store.Sessions().Create(ctx, porte.Session{
				TokenHash: "h" + email, UserID: squatter, CreatedAt: time.Now(), LastUsedAt: time.Now(),
				Provider: "https://sso.test", Subject: "att" + email,
			})
		}()
		go func() {
			defer wg.Done()
			_, _ = store.Users().UpsertFromOIDC(ctx, claims("vic"+email, email, true))
		}()
		wg.Wait()
		if identityCount(t, db, squatter, "vic"+email) == 1 && len(leftovers(t, db, squatter)) != 0 {
			t.Fatalf("iteration %d: the squatter's session survived on the owner's account", i)
		}
	}
}
