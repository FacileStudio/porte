package kit_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/kit"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const testSchema = "porte_kit_test"

const usersDDL = `
DROP TABLE IF EXISTS porte_identities, monitors, users, accounts, gorm_users, members CASCADE;
CREATE TABLE users (
	id bigserial PRIMARY KEY, email text NOT NULL UNIQUE, name text NOT NULL DEFAULT '',
	avatar_url text NOT NULL DEFAULT '', locale text NOT NULL DEFAULT 'en', is_admin boolean NOT NULL DEFAULT false,
	created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE gorm_users (
	id bigserial PRIMARY KEY, email text, name text, avatar_url text, locale text NOT NULL DEFAULT 'en',
	is_admin boolean DEFAULT false, password_hash text, created_at timestamptz, updated_at timestamptz);
CREATE TABLE members (
	id bigserial PRIMARY KEY, email text, name text, avatar_url text, locale text,
	joined_at timestamptz, touched_at timestamptz);
CREATE TABLE accounts (
	account_id bigserial PRIMARY KEY, mail text UNIQUE, display text, picture_url text,
	locale text NOT NULL DEFAULT 'en', color text);
CREATE TABLE monitors (owner_id bigint NOT NULL);
CREATE TABLE porte_identities (
	user_id bigint NOT NULL, provider text NOT NULL, subject text NOT NULL, PRIMARY KEY (provider, subject));`

// openDB returns a connection whose search_path is a schema of its own, so
// these tables never meet porte/pg's, whose tests run in parallel with these.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("PORTE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PORTE_TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+testSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	db, err := sql.Open("pgx", url+separator+"search_path="+testSchema)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, usersDDL); err != nil {
		t.Fatalf("tables: %v", err)
	}
	return db
}

func adminStore(t *testing.T) (*kit.Store, *sql.DB) {
	t.Helper()
	db := openDB(t)
	return &kit.Store{DB: db, Columns: kit.Columns{Admin: "is_admin"}}, db
}

func claimsFor(subject, email string, verified bool) porte.Claims {
	return porte.Claims{
		Provider: fakeIssuer, Subject: subject, Email: email, EmailVerified: verified,
		Name: "Camille", Picture: fakeIssuer + "/avatars/" + subject, Locale: "fr",
	}
}

// signIn is what porte/oidc does around the store: upsert, then record the
// identity row against the returned user.
func signIn(t *testing.T, store *kit.Store, claims porte.Claims) (int64, error) {
	t.Helper()
	userID, err := store.UpsertFromOIDC(context.Background(), claims)
	if err != nil {
		return 0, err
	}
	_, err = store.DB.ExecContext(context.Background(),
		`INSERT INTO porte_identities (user_id, provider, subject) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		userID, claims.Provider, claims.Subject)
	if err != nil {
		t.Fatalf("identity row: %v", err)
	}
	return userID, nil
}

func mustSignIn(t *testing.T, store *kit.Store, claims porte.Claims) int64 {
	t.Helper()
	userID, err := signIn(t, store, claims)
	if err != nil {
		t.Fatalf("sign-in %s: %v", claims.Subject, err)
	}
	return userID
}

func column(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	var value sql.NullString
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&value); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return value.String
}
