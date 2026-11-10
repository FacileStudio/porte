package kit_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func eraseMonitors(ctx context.Context, tx *sql.Tx, userID int64) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM monitors WHERE owner_id = $1`, userID)
	return err
}

func TestEraseAccountDeletesThePersonAndTheirDataOnce(t *testing.T) {
	store, db := adminStore(t)
	store.EraseData = eraseMonitors
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	other := mustSignIn(t, store, claimsFor("sub-2", "dominique@facile.studio", true))
	if _, err := db.Exec(`INSERT INTO monitors (owner_id) VALUES ($1), ($1), ($2)`, userID, other); err != nil {
		t.Fatalf("monitors: %v", err)
	}
	for range 2 {
		if err := store.EraseAccount(context.Background(), fakeIssuer, "sub-1"); err != nil {
			t.Fatalf("erase: %v", err)
		}
	}
	left := column(t, db, `SELECT (SELECT count(*) FROM users)::text || '/' || (SELECT count(*) FROM monitors)::text`)
	if left != "1/1" {
		t.Fatalf("users/monitors left = %s, want 1/1", left)
	}
	if err := store.EraseAccount(context.Background(), fakeIssuer, "nobody"); err != nil {
		t.Fatalf("an unknown identity: %v", err)
	}
}

func TestAFailingEraseHookKeepsTheAccount(t *testing.T) {
	store, db := adminStore(t)
	store.EraseData = func(ctx context.Context, tx *sql.Tx, userID int64) error {
		if err := eraseMonitors(ctx, tx, userID); err != nil {
			return err
		}
		return errors.New("app data refused")
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if _, err := db.Exec(`INSERT INTO monitors (owner_id) VALUES ($1)`, userID); err != nil {
		t.Fatalf("monitor: %v", err)
	}
	if err := store.EraseAccount(context.Background(), fakeIssuer, "sub-1"); err == nil {
		t.Fatal("a failing hook reported success")
	}
	left := column(t, db, `SELECT (SELECT count(*) FROM users)::text || '/' || (SELECT count(*) FROM monitors)::text`)
	if left != "1/1" {
		t.Fatalf("users/monitors left = %s, want 1/1: the hook's delete was not rolled back", left)
	}
}

func TestBackfillFillsOnlyEmptyPictures(t *testing.T) {
	store, db := adminStore(t)
	first := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	plain := claimsFor("sub-2", "dominique@facile.studio", true)
	plain.Picture = ""
	second := mustSignIn(t, store, plain)
	if _, err := db.Exec(`UPDATE users SET avatar_url = 'https://cdn.test/kept' WHERE id = $1`, first); err != nil {
		t.Fatalf("seed: %v", err)
	}
	filled, err := store.BackfillPictures(context.Background(), fakeIssuer+"/")
	if err != nil || filled != 1 {
		t.Fatalf("filled %d, %v", filled, err)
	}
	got := column(t, db, `SELECT string_agg(avatar_url, ' ' ORDER BY id) FROM users WHERE id IN ($1, $2)`, first, second)
	if got != "https://cdn.test/kept "+fakeIssuer+"/avatars/sub-2" {
		t.Fatalf("pictures = %q", got)
	}
	if filled, err := store.BackfillPictures(context.Background(), "http://sso.test"); err != nil || filled != 0 {
		t.Fatalf("a plain http issuer filled %d, %v", filled, err)
	}
}
