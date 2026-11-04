package pg_test

import (
	"context"
	"database/sql"
	"testing"
)

// readLocale is the stored locale of one user.
func readLocale(t *testing.T, db *sql.DB, userID int64) string {
	t.Helper()
	var locale string
	if err := db.QueryRowContext(context.Background(), `SELECT locale FROM porte_users WHERE id = $1`, userID).Scan(&locale); err != nil {
		t.Fatalf("read locale: %v", err)
	}
	return locale
}

// TestUpsertStoresTheNormalisedLocale pins the column: written normalised on
// insert and on update, and kept when a caller builds Claims without one.
func TestUpsertStoresTheNormalisedLocale(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	users := store.Users()
	read := func(userID int64) string { return readLocale(t, db, userID) }
	steps := []struct{ claimed, want string }{{"fr-FR", "fr"}, {"de", "de"}, {"", "de"}, {"klingon", "en"}}
	for _, step := range steps {
		c := claims("sub-1", "camille@facile.studio", true)
		c.Locale = step.claimed
		userID, err := users.UpsertFromOIDC(ctx, c)
		if err != nil {
			t.Fatalf("upsert %q: %v", step.claimed, err)
		}
		if got := read(userID); got != step.want {
			t.Errorf("after locale %q the column holds %q, want %q", step.claimed, got, step.want)
		}
	}
	c := claims("sub-2", "remy@facile.studio", true)
	c.Locale = "es-419"
	userID, err := users.UpsertFromOIDC(ctx, c)
	if err != nil || read(userID) != "es" {
		t.Errorf("a new user's locale was not stored normalised: %v", err)
	}
	passwordUser, err := users.CreateFromPassword(ctx, "nina@facile.studio", "Nina")
	if err != nil || read(passwordUser) != "en" {
		t.Errorf("a password user did not default to en: %v", err)
	}
}
