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

// oldDDL is the v0.9.0 shape of the tables an adopter that owns its DDL
// still has: no locale, no binding columns.
const oldDDL = `
DROP SCHEMA IF EXISTS porte_old CASCADE;
CREATE SCHEMA porte_old;
CREATE TABLE porte_old.porte_users (
	id bigserial PRIMARY KEY, facile_id text UNIQUE, email text NOT NULL UNIQUE,
	email_verified boolean NOT NULL DEFAULT false, name text NOT NULL DEFAULT '',
	avatar_url text NOT NULL DEFAULT '', avatar_source text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE porte_old.porte_identities (
	user_id bigint NOT NULL REFERENCES porte_old.porte_users(id) ON DELETE CASCADE,
	provider text NOT NULL, subject text NOT NULL, password_hash text NOT NULL DEFAULT '',
	access_token text NOT NULL DEFAULT '', refresh_token text NOT NULL DEFAULT '',
	token_expiry timestamptz, roles jsonb, roles_synced_at timestamptz, synced_at timestamptz,
	created_at timestamptz DEFAULT now(), PRIMARY KEY (provider, subject));
CREATE TABLE porte_old.porte_sessions (
	id bigserial PRIMARY KEY, token_hash text NOT NULL UNIQUE,
	user_id bigint NOT NULL REFERENCES porte_old.porte_users(id) ON DELETE CASCADE,
	label text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
	last_used_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz);
CREATE TABLE porte_old.porte_login_codes (
	code_hash text PRIMARY KEY,
	user_id bigint NOT NULL REFERENCES porte_old.porte_users(id) ON DELETE CASCADE,
	expires_at timestamptz NOT NULL, consumed_at timestamptz);
`

// openOldDDL is a store over the v0.9.0 tables, through a pool whose
// search_path finds them first.
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

// TestAnAppWithItsOwnOldDDLStillIssuesSessions: an adopter that has not run
// the new migration yet keeps password and API sessions, bound OIDC sessions
// and unbound codes. Only a bound code needs the new columns.
func TestAnAppWithItsOwnOldDDLStillIssuesSessions(t *testing.T) {
	store, db := openOldDDL(t)
	ctx := context.Background()
	var userID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO porte_users (email) VALUES ('old@example.test') RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, 'https://sso.test', 'old-sub')`, userID); err != nil {
		t.Fatalf("identity: %v", err)
	}
	for _, s := range []porte.Session{
		{UserID: userID, TokenHash: "unbound"},
		{UserID: userID, TokenHash: "bound", Provider: "https://sso.test", Subject: "old-sub"},
	} {
		s.CreatedAt, s.LastUsedAt = time.Now(), time.Now()
		if _, err := store.Sessions().Create(ctx, s); err != nil {
			t.Errorf("%s session on the old DDL: %v", s.TokenHash, err)
		}
	}
	code := porte.LoginCode{CodeHash: "old-code", UserID: userID, ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.LoginCodes().Create(ctx, code); err != nil {
		t.Fatalf("unbound code on the old DDL: %v", err)
	}
	if got, err := store.LoginCodes().Consume(ctx, "old-code"); err != nil || got.UserID != userID || got.Provider != "" {
		t.Errorf("consume on the old DDL = %+v, %v", got, err)
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
