package kit_test

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/kit"
)

func newStore(t *testing.T, store kit.Store) (*kit.Store, string) {
	t.Helper()
	var logs bytes.Buffer
	store.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	built, err := kit.NewStore(context.Background(), store)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return built, logs.String()
}

func ageTimestamps(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE `+table+` SET created_at = '2000-01-01', updated_at = '2000-01-01'`); err != nil {
		t.Fatalf("age: %v", err)
	}
}

func TestATableWithDefaultsReportsNothingAndKeepsItsTimestamps(t *testing.T) {
	db := openDB(t)
	store, logs := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Admin: "is_admin"}})
	if got := store.Unwritten(); len(got) != 0 || logs != "" {
		t.Fatalf("unwritten %v, logs %q", got, logs)
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	ageTimestamps(t, db, "users")
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if got := column(t, db, `SELECT (created_at = updated_at AND updated_at < '2001-01-01')::text FROM users WHERE id = $1`,
		userID); got != "true" {
		t.Fatal("the kit wrote a timestamp the database fills by default")
	}
}

func TestAGormTableGetsItsTimestampsAndReportsTheRest(t *testing.T) {
	db := openDB(t)
	store, logs := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Table: "gorm_users", Admin: "is_admin"}})
	if got := store.Unwritten(); !slices.Equal(got, []string{"password_hash"}) {
		t.Fatalf("unwritten = %v", got)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "password_hash") || !strings.Contains(logs, "NULL") {
		t.Fatalf("logs = %q", logs)
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	stamped := `SELECT (created_at > now() - interval '1 minute' AND updated_at = created_at)::text FROM gorm_users WHERE id = $1`
	if got := column(t, db, stamped, userID); got != "true" {
		t.Fatal("a new account has no created_at or updated_at")
	}
	ageTimestamps(t, db, "gorm_users")
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	moved := `SELECT (created_at < '2001-01-01' AND updated_at > now() - interval '1 minute')::text FROM gorm_users WHERE id = $1`
	if got := column(t, db, moved, userID); got != "true" {
		t.Fatal("a sign-in did not move updated_at, or moved created_at")
	}
}

func TestTheBackfillMovesUpdatedAt(t *testing.T) {
	db := openDB(t)
	store, _ := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Table: "gorm_users"}})
	claims := claimsFor("sub-1", "camille@facile.studio", true)
	claims.Picture = ""
	userID := mustSignIn(t, store, claims)
	ageTimestamps(t, db, "gorm_users")
	if filled, err := store.BackfillPictures(context.Background(), fakeIssuer); err != nil || filled != 1 {
		t.Fatalf("backfill %d, %v", filled, err)
	}
	if got := column(t, db, `SELECT (updated_at > '2001-01-01')::text FROM gorm_users WHERE id = $1`, userID); got != "true" {
		t.Fatal("the backfill did not move updated_at")
	}
}

func TestOnCreateWinsOverTheKitsTimestamps(t *testing.T) {
	db := openDB(t)
	onCreate := func(ctx context.Context, tx *sql.Tx, userID int64) error {
		_, err := tx.ExecContext(ctx, `UPDATE gorm_users SET created_at = '2001-02-03', password_hash = '' WHERE id = $1`, userID)
		return err
	}
	store, logs := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Table: "gorm_users"}, OnCreate: onCreate})
	if logs != "" || !slices.Equal(store.Unwritten(), []string{"password_hash"}) {
		t.Fatalf("logs %q, unwritten %v", logs, store.Unwritten())
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	got := column(t, db, `SELECT created_at::date::text || '|' || password_hash FROM gorm_users WHERE id = $1`, userID)
	if got != "2001-02-03|" {
		t.Fatalf("created_at|password_hash = %q", got)
	}
}

func TestExplicitTimestampColumns(t *testing.T) {
	db := openDB(t)
	detected, _ := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Table: "members"}})
	if got := detected.Unwritten(); !slices.Equal(got, []string{"joined_at", "touched_at"}) {
		t.Fatalf("unnamed timestamps: unwritten = %v", got)
	}
	store, logs := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Table: "members", CreatedAt: "joined_at", UpdatedAt: "touched_at"}})
	if len(store.Unwritten()) != 0 || logs != "" {
		t.Fatalf("unwritten %v, logs %q", store.Unwritten(), logs)
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if _, err := db.ExecContext(context.Background(), `UPDATE members SET touched_at = '2000-01-01'`); err != nil {
		t.Fatalf("age: %v", err)
	}
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	got := column(t, db, `SELECT (joined_at IS NOT NULL AND touched_at > '2001-01-01')::text FROM members WHERE id = $1`, userID)
	if got != "true" {
		t.Fatal("the named timestamp columns were not written")
	}
}

func TestATableWithNeitherTimestamp(t *testing.T) {
	db := openDB(t)
	columns := kit.Columns{Table: "accounts", ID: "account_id", Email: "mail", Name: "display", Picture: "picture_url"}
	store, _ := newStore(t, kit.Store{DB: db, Columns: columns})
	if got := store.Unwritten(); !slices.Equal(got, []string{"color"}) {
		t.Fatalf("unwritten = %v", got)
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if got := column(t, db, `SELECT mail FROM accounts WHERE account_id = $1`, userID); got != "camille@facile.studio" {
		t.Fatalf("mail = %q", got)
	}
}

func TestNewStoreRefusesAMissingTableOrColumn(t *testing.T) {
	db := openDB(t)
	for _, columns := range []kit.Columns{{Table: "nowhere"}, {Table: "accounts"}, {UpdatedAt: "modified"}} {
		if _, err := kit.NewStore(context.Background(), kit.Store{DB: db, Columns: columns}); err == nil {
			t.Fatalf("%+v: no error", columns)
		}
	}
}
