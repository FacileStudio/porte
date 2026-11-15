package kit_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/porte/kit"
	"github.com/FacileStudio/porte/pg"
)

func registreListing(t *testing.T, subjects ...string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if r.URL.Path != "/api/directory/deletions" || !ok || id != "agenda" || secret != "s3cret" {
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		listed := []directory.Deleted{}
		for _, subject := range subjects {
			listed = append(listed, directory.Deleted{Subject: subject, DeletedAt: time.Now().Add(-time.Hour)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": listed})
	}))
	t.Cleanup(server.Close)
	return server
}

// erasableAccount adds the two tables an erasure touches beyond the kit's
// own: porte's sessions, and the receiver's state.
func erasableAccount(t *testing.T) (*kit.Store, *sql.DB) {
	t.Helper()
	users, db := adminStore(t)
	_, err := db.Exec(`DROP TABLE IF EXISTS directory_deletion_state, porte_sessions;
		CREATE TABLE porte_sessions (user_id bigint NOT NULL);` + pg.DeletionStateSchema)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	return users, db
}

func TestNewDeletionsErasesAPersonRegistreListsExactlyOnce(t *testing.T) {
	users, db := erasableAccount(t)
	registre := registreListing(t, "sub-1")
	claims := claimsFor("sub-1", "camille@facile.studio", true)
	claims.Provider = registre.URL
	mustSignIn(t, users, claims)

	calls := 0
	receiver, err := kit.NewDeletions(kit.DeletionsConfig{
		OIDC:  porte.Config{Issuer: registre.URL, ClientID: "agenda", ClientSecret: "s3cret"},
		Store: pg.New(db),
		OnPersonDeleted: func(ctx context.Context, provider, subject string) error {
			calls++
			return users.EraseAccount(ctx, provider, subject)
		},
	})
	if err != nil {
		t.Fatalf("NewDeletions: %v", err)
	}
	receiver.Client.HTTP = &http.Client{Transport: &http.Transport{}}
	for range 2 {
		if err := receiver.Poll(context.Background()); err != nil {
			t.Fatalf("poll: %v", err)
		}
	}
	left := column(t, db, `SELECT (SELECT count(*) FROM users)::text || '/' || (SELECT count(*) FROM porte_identities)::text`)
	if calls != 1 || left != "0/0" {
		t.Fatalf("callback ran %d times, users/identities left = %s; want 1 and 0/0", calls, left)
	}
	erased, err := kit.ErasedGuard(receiver).Erased(context.Background(), registre.URL, "sub-1")
	if err != nil || !erased {
		t.Fatalf("Erased = %v, %v, want the handled subject refused", erased, err)
	}
}

func TestNewDeletionsWithoutAnIssuerBuildsNothing(t *testing.T) {
	receiver, err := kit.NewDeletions(kit.DeletionsConfig{})
	if receiver != nil || err != nil {
		t.Fatalf("NewDeletions = %v, %v, want nil, nil without an issuer", receiver, err)
	}
	if guard := kit.ErasedGuard(receiver); guard != nil {
		t.Fatalf("ErasedGuard(nil) = %#v, want a nil interface", guard)
	}
}

func TestNewDeletionsRefusesAReceiverThatCouldEraseNothing(t *testing.T) {
	oidc := porte.Config{Issuer: "https://sso.test", ClientID: "agenda", ClientSecret: "s3cret"}
	noop := func(context.Context, string, string) error { return nil }
	for name, cfg := range map[string]kit.DeletionsConfig{
		"no store":    {OIDC: oidc, OnPersonDeleted: noop},
		"no callback": {OIDC: oidc, Store: pg.New(nil)},
	} {
		if _, err := kit.NewDeletions(cfg); !errors.Is(err, kit.ErrDeletionsIncomplete) {
			t.Errorf("%s: err = %v, want ErrDeletionsIncomplete", name, err)
		}
	}
}
