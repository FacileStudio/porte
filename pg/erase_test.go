package pg_test

import (
	"context"
	"database/sql"
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
