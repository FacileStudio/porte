package kit_test

import (
	"context"
	"database/sql"
	stderrors "errors"
	"net/http"
	"sync"
	"testing"

	"github.com/FacileStudio/porte/kit"
	"github.com/FacileStudio/tronc/errors"
)

func statusOf(err error) int {
	var apiErr *errors.Error
	if !stderrors.As(err, &apiErr) {
		return 0
	}
	return errors.Status(apiErr)
}

func TestTheFirstAccountIsAdminAndTheSecondIsNot(t *testing.T) {
	store, _ := adminStore(t)
	first := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	second := mustSignIn(t, store, claimsFor("sub-2", "dominique@facile.studio", true))
	a, errA := store.Identity(context.Background(), first)
	b, errB := store.Identity(context.Background(), second)
	if errA != nil || errB != nil || !a.IsAdmin || b.IsAdmin {
		t.Fatalf("first %+v (%v), second %+v (%v)", a, errA, b, errB)
	}
}

func TestTwoSimultaneousFirstSignInsMakeOneAdmin(t *testing.T) {
	store, db := adminStore(t)
	var wait sync.WaitGroup
	for _, subject := range []string{"sub-1", "sub-2", "sub-3", "sub-4"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = store.UpsertFromOIDC(context.Background(), claimsFor(subject, subject+"@facile.studio", true))
		}()
	}
	wait.Wait()
	if admins := column(t, db, `SELECT count(*)::text FROM users WHERE is_admin`); admins != "1" {
		t.Fatalf("%s administrators", admins)
	}
}

func TestASubjectSignsBackInAndRefreshesOnlyWhatTheProviderSent(t *testing.T) {
	store, db := adminStore(t)
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	renamed := claimsFor("sub-1", "Camille.B@facile.studio", true)
	renamed.Name, renamed.Locale, renamed.Picture = "", "", "data:image/svg+xml;base64,AA"
	if again := mustSignIn(t, store, renamed); again != userID {
		t.Fatalf("a renamed email forked the account: %d then %d", userID, again)
	}
	got := column(t, db, `SELECT email || '|' || name || '|' || locale || '|' || avatar_url FROM users WHERE id = $1`, userID)
	if got != "camille.b@facile.studio|Camille|fr|" {
		t.Fatalf("profile = %q", got)
	}
}

func TestAVerifiedEmailLinksAnExistingAccount(t *testing.T) {
	store, db := adminStore(t)
	existing := column(t, db, `INSERT INTO users (email) VALUES ('camille@facile.studio') RETURNING id::text`)
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if got := column(t, db, `SELECT id::text FROM users WHERE id = $1`, userID); got != existing {
		t.Fatalf("linked %s, want %s", got, existing)
	}
}

func TestAnUnverifiedEmailNeverLinksNorMovesAnAddress(t *testing.T) {
	store, db := adminStore(t)
	_ = column(t, db, `INSERT INTO users (email) VALUES ('camille@facile.studio') RETURNING id::text`)
	if _, err := signIn(t, store, claimsFor("sub-1", "camille@facile.studio", false)); statusOf(err) != http.StatusConflict {
		t.Fatalf("unverified link: %v", err)
	}
	userID := mustSignIn(t, store, claimsFor("sub-2", "dominique@facile.studio", true))
	mustSignIn(t, store, claimsFor("sub-2", "attacker@evil.test", false))
	if got := column(t, db, `SELECT email FROM users WHERE id = $1`, userID); got != "dominique@facile.studio" {
		t.Fatalf("an unverified claim moved the address to %q", got)
	}
}

func TestARecycledAddressIsNotHandedToANewSubject(t *testing.T) {
	store, _ := adminStore(t)
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if _, err := signIn(t, store, claimsFor("sub-2", "camille@facile.studio", true)); statusOf(err) != http.StatusConflict {
		t.Fatalf("recycled address: %v", err)
	}
}

func TestAnUnusableEmailIsRefused(t *testing.T) {
	store, _ := adminStore(t)
	for _, email := range []string{"", "not-an-address", "Camille <camille@facile.studio>"} {
		if _, err := store.UpsertFromOIDC(context.Background(), claimsFor("sub-1", email, true)); statusOf(err) != http.StatusBadRequest {
			t.Fatalf("%q: %v", email, err)
		}
	}
}

func TestIdentityRefusesAUserThatIsGone(t *testing.T) {
	store, _ := adminStore(t)
	if _, err := store.Identity(context.Background(), 4242); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("missing user: %v", err)
	}
}

func TestCustomColumnsAndTheCreateHook(t *testing.T) {
	db := openDB(t)
	store := &kit.Store{
		DB:      db,
		Columns: kit.Columns{Table: "accounts", ID: "account_id", Email: "mail", Name: "display", Picture: "picture_url"},
	}
	store.OnCreate = func(ctx context.Context, tx *sql.Tx, userID int64) error {
		_, err := tx.ExecContext(ctx, `UPDATE accounts SET color = 'teal' WHERE account_id = $1`, userID)
		return err
	}
	userID := mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	identity, err := store.Identity(context.Background(), userID)
	if err != nil || identity.IsAdmin || identity.Email != "camille@facile.studio" || identity.PictureURL != fakeIssuer+"/avatars/sub-1" {
		t.Fatalf("identity %+v, %v", identity, err)
	}
	if color := column(t, db, `SELECT color FROM accounts WHERE account_id = $1`, userID); color != "teal" {
		t.Fatalf("color = %q", color)
	}
}
