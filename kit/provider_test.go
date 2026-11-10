package kit_test

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/porte/kit"
)

type spelling struct{ name, stored, presented string }

func spellings(issuer string) []spelling {
	forms := map[string]string{"bare": issuer, "slashed": issuer + "/"}
	var out []spelling
	for storedName, stored := range forms {
		for presentedName, presented := range forms {
			out = append(out, spelling{name: storedName + " stored, " + presentedName + " presented", stored: stored, presented: presented})
		}
	}
	return out
}

func storedAs(t *testing.T, store *kit.Store, provider, subject, email string) int64 {
	t.Helper()
	claims := claimsFor(subject, email, true)
	claims.Provider = provider
	claims.Picture = ""
	return mustSignIn(t, store, claims)
}

func presentedAs(provider, subject, email string, verified bool) porte.Claims {
	claims := claimsFor(subject, email, verified)
	claims.Provider = provider
	return claims
}

func TestSignInFindsTheSubjectUnderEitherSpelling(t *testing.T) {
	for _, s := range spellings(fakeIssuer) {
		t.Run(s.name, func(t *testing.T) {
			store, _ := adminStore(t)
			userID := storedAs(t, store, s.stored, "sub-1", "camille@facile.studio")
			got, err := store.UpsertFromOIDC(context.Background(), presentedAs(s.presented, "sub-1", "elsewhere@facile.studio", false))
			if err != nil || got != userID {
				t.Fatalf("sign-in found %d, %v, want %d", got, err, userID)
			}
		})
	}
}

func TestASecondSubjectIsRefusedUnderEitherSpelling(t *testing.T) {
	for _, s := range spellings(fakeIssuer) {
		t.Run(s.name, func(t *testing.T) {
			store, db := adminStore(t)
			storedAs(t, store, s.stored, "sub-1", "camille@facile.studio")
			_, err := store.UpsertFromOIDC(context.Background(), presentedAs(s.presented, "sub-2", "camille@facile.studio", true))
			if err == nil || !strings.Contains(err.Error(), "another identity from the same provider") {
				t.Fatalf("a second subject was not refused: %v", err)
			}
			if count := column(t, db, `SELECT count(*)::text FROM users`); count != "1" {
				t.Fatalf("users = %s, want 1", count)
			}
		})
	}
}

func TestTheExactSpellingWinsWhenBothAreStored(t *testing.T) {
	store, _ := adminStore(t)
	bare := storedAs(t, store, fakeIssuer, "sub-1", "camille@facile.studio")
	slashed := storedAs(t, store, fakeIssuer+"/", "sub-1", "dominique@facile.studio")
	for provider, want := range map[string]int64{fakeIssuer: bare, fakeIssuer + "/": slashed} {
		got, err := store.UpsertFromOIDC(context.Background(), presentedAs(provider, "sub-1", "elsewhere@facile.studio", false))
		if err != nil || got != want {
			t.Fatalf("%s found %d, %v, want %d", provider, got, err, want)
		}
	}
}

func TestEraseFindsTheSubjectUnderEitherSpelling(t *testing.T) {
	for _, s := range spellings(fakeIssuer) {
		t.Run(s.name, func(t *testing.T) {
			store, db := adminStore(t)
			store.EraseData = eraseMonitors
			userID := storedAs(t, store, s.stored, "sub-1", "camille@facile.studio")
			if _, err := db.Exec(`INSERT INTO monitors (owner_id) VALUES ($1)`, userID); err != nil {
				t.Fatalf("monitor: %v", err)
			}
			if err := store.EraseAccount(context.Background(), s.presented, "sub-1"); err != nil {
				t.Fatalf("erase: %v", err)
			}
			left := column(t, db, `SELECT (SELECT count(*) FROM users)::text || '/' || (SELECT count(*) FROM monitors)::text`)
			if left != "0/0" {
				t.Fatalf("users/monitors left = %s, want 0/0", left)
			}
		})
	}
}

func TestBackfillMatchesEitherSpelling(t *testing.T) {
	for _, s := range spellings(fakeIssuer) {
		t.Run(s.name, func(t *testing.T) {
			store, db := adminStore(t)
			userID := storedAs(t, store, s.stored, "sub-1", "camille@facile.studio")
			filled, err := store.BackfillPictures(context.Background(), s.presented)
			if err != nil || filled != 1 {
				t.Fatalf("filled %d, %v", filled, err)
			}
			if got := column(t, db, `SELECT avatar_url FROM users WHERE id = $1`, userID); got != fakeIssuer+"/avatars/sub-1" {
				t.Fatalf("picture = %q", got)
			}
		})
	}
}

type sqlIdentities struct{ db *sql.DB }

func (s sqlIdentities) ListByUser(ctx context.Context, userID int64) ([]porte.StoredIdentity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider, subject FROM porte_identities WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []porte.StoredIdentity
	for rows.Next() {
		identity := porte.StoredIdentity{UserID: userID}
		if err := rows.Scan(&identity.Provider, &identity.Subject); err != nil {
			return nil, err
		}
		out = append(out, identity)
	}
	return out, rows.Err()
}

func invitationsFor(t *testing.T, fake *registreFake, issuer string, db *sql.DB) *kit.Invitations {
	t.Helper()
	handler, err := kit.NewInvitations(kit.InvitationsConfig{
		Directory:  directory.Client{Issuer: issuer, ClientID: "nuage", ClientSecret: "s3cret", HTTP: fake.server.Client()},
		Identities: sqlIdentities{db: db},
		Logger:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestInvitationsFindTheSubjectUnderEitherSpelling(t *testing.T) {
	fake := newRegistreFake(t, 1)
	for _, s := range spellings(fake.server.URL) {
		t.Run(s.name, func(t *testing.T) {
			store, db := adminStore(t)
			userID := storedAs(t, store, s.stored, "sub-1", "camille@facile.studio")
			h := &harness{fake: fake, handler: invitationsFor(t, fake, s.presented, db)}
			if body := h.ask(t, userID); body["count"] != float64(1) {
				t.Fatalf("invitations answered %v", body)
			}
		})
	}
}
