package pg_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
)

func count(t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, table string, userID int64) int {
	t.Helper()
	var n int
	if err := q.QueryRowContext(context.Background(), "SELECT count(*) FROM "+table+" WHERE user_id = $1", userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func seedPerson(t *testing.T, store *pg.Store, who string) int64 {
	t.Helper()
	ctx, now := context.Background(), time.Now()
	id, err := store.Users().UpsertFromOIDC(ctx, claims(who, who+"@facile.test", true))
	if err != nil {
		t.Fatal(err)
	}
	login := porte.Session{UserID: id, TokenHash: "s-" + who, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	token := porte.Session{UserID: id, TokenHash: "t-" + who, Label: "cli", CreatedAt: now, LastUsedAt: now}
	code := porte.LoginCode{CodeHash: "c-" + who, UserID: id, ExpiresAt: now.Add(time.Minute)}
	for _, session := range []porte.Session{login, token} {
		if _, err := store.Sessions().Create(ctx, session); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.LoginCodes().Create(ctx, code); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEraseIdentityRemovesPorteRowsOfThatPersonOnly(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	alice, bob := seedPerson(t, store, "alice"), seedPerson(t, store, "bob")
	if err := store.EraseIdentity(ctx, "https://sso.test", "alice"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"porte_identities", "porte_sessions", "porte_login_codes"} {
		if n := count(t, db, table, alice); n != 0 {
			t.Errorf("%s still holds %d rows of the erased person", table, n)
		}
		if n := count(t, db, table, bob); n == 0 {
			t.Errorf("%s lost the other person's rows", table)
		}
	}
	if err := store.EraseIdentity(ctx, "https://sso.test", "alice"); err != nil {
		t.Fatalf("second erase = %v, want a no-op", err)
	}
}

func openWithout(t *testing.T, schema string, drop ...string) (*pg.Store, *sql.DB) {
	t.Helper()
	url := os.Getenv("PORTE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PORTE_TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if _, err := admin.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE; CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE") })
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	db, err := sql.Open("pgx", url+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := pg.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, table := range drop {
		if _, err := db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			t.Fatal(err)
		}
	}
	return pg.New(db), db
}

func TestEraseIdentitySkipsOptionalTablesTheSchemaLacks(t *testing.T) {
	cases := map[string][]string{
		"porte_t_nomagic": {"porte_magic_links"},
		"porte_t_nocodes": {"porte_login_codes", "porte_magic_links"},
	}
	for schema, drop := range cases {
		t.Run(schema, func(t *testing.T) {
			store, db := openWithout(t, schema, drop...)
			ctx := context.Background()
			alice, bob := seedPersonWithoutCodes(t, store, "alice"), seedPersonWithoutCodes(t, store, "bob")
			if err := store.EraseIdentity(ctx, "https://sso.test", "alice"); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"porte_identities", "porte_sessions"} {
				if n := count(t, db, table, alice); n != 0 {
					t.Errorf("%s still holds %d rows of the erased person", table, n)
				}
				if n := count(t, db, table, bob); n == 0 {
					t.Errorf("%s lost the other person's rows", table)
				}
			}
			if err := store.EraseIdentity(ctx, "https://sso.test", "alice"); err != nil {
				t.Fatalf("second erase = %v, want a no-op", err)
			}
		})
	}
}

func seedPersonWithoutCodes(t *testing.T, store *pg.Store, who string) int64 {
	t.Helper()
	ctx, now := context.Background(), time.Now()
	id, err := store.Users().UpsertFromOIDC(ctx, claims(who, who+"@facile.test", true))
	if err != nil {
		t.Fatal(err)
	}
	session := porte.Session{UserID: id, TokenHash: "s-" + who, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.Sessions().Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEraseIdentityStillFailsWithoutRequiredTables(t *testing.T) {
	store, db := openWithout(t, "porte_t_nosessions")
	ctx := context.Background()
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("alice", "alice@facile.test", true)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE porte_sessions"); err != nil {
		t.Fatal(err)
	}
	if err := store.EraseIdentity(ctx, "https://sso.test", "alice"); err == nil {
		t.Fatal("erase succeeded without porte_sessions, want an error")
	}
}

func TestUnverifiedTakeoverPurgeSkipsMissingOptionalTables(t *testing.T) {
	store, _ := openWithout(t, "porte_t_purge", "porte_magic_links")
	ctx := context.Background()
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("squatter", "victim@facile.test", false)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("victim", "victim@facile.test", true)); err != nil {
		t.Fatalf("takeover purge = %v", err)
	}
}
