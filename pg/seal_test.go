package pg_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
)

const sealProvider = "https://sso.test"

func sealedFixture(t *testing.T, sealer *pg.TokenSealer) (*pg.IdentityStore, *sql.DB, int64) {
	t.Helper()
	_, db := open(t)
	store := pg.New(db, pg.WithTokenSealer(sealer))
	userID, err := store.Users().UpsertFromOIDC(context.Background(), claims("sub-seal", "seal@facile.studio", true))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return store.Identities(), db, userID
}

func saveTokens(t *testing.T, ids *pg.IdentityStore, userID int64, access, refresh string) {
	t.Helper()
	err := ids.Save(context.Background(), porte.StoredIdentity{
		UserID: userID, Provider: sealProvider, Subject: "sub-seal",
		Tokens: porte.TokenSet{AccessToken: access, RefreshToken: refresh},
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
}

func rawTokens(t *testing.T, db *sql.DB) (access, refresh string) {
	t.Helper()
	err := db.QueryRow(`SELECT access_token, refresh_token FROM porte_identities WHERE subject = 'sub-seal'`).
		Scan(&access, &refresh)
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	return access, refresh
}

func findTokens(t *testing.T, ids *pg.IdentityStore) porte.TokenSet {
	t.Helper()
	got, err := ids.Find(context.Background(), sealProvider, "sub-seal")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	return got.Tokens
}

func TestSealedTokensRoundTripAndAreCiphertextAtRest(t *testing.T) {
	ids, db, userID := sealedFixture(t, mustSealer(t, secret(1)))
	saveTokens(t, ids, userID, "access-secret", "refresh-secret")
	access, refresh := rawTokens(t, db)
	if !strings.HasPrefix(access, "pv1:") || !strings.HasPrefix(refresh, "pv1:") ||
		strings.Contains(access+refresh, "secret") {
		t.Fatalf("stored in the clear: %q %q", access, refresh)
	}
	if got := findTokens(t, ids); got.AccessToken != "access-secret" || got.RefreshToken != "refresh-secret" {
		t.Fatalf("round trip = %+v", got)
	}
	list, err := ids.ListByUser(context.Background(), userID)
	if err != nil || len(list) == 0 || list[0].Tokens.RefreshToken != "refresh-secret" {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestPlaintextRowsStayReadableAndWithoutASealerNothingChanges(t *testing.T) {
	ids, db, userID := sealedFixture(t, nil)
	saveTokens(t, ids, userID, "at", "rt")
	if access, refresh := rawTokens(t, db); access != "at" || refresh != "rt" {
		t.Fatalf("no sealer must store plaintext: %q %q", access, refresh)
	}
	sealed := pg.New(db, pg.WithTokenSealer(mustSealer(t, secret(1)))).Identities()
	if got := findTokens(t, sealed); got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Fatalf("plaintext row = %+v", got)
	}
}

func TestWrongKeyTreatsTheIdentityAsHavingNoToken(t *testing.T) {
	ids, db, userID := sealedFixture(t, mustSealer(t, secret(1)))
	saveTokens(t, ids, userID, "at", "rt")
	other := pg.New(db, pg.WithTokenSealer(mustSealer(t, secret(2)))).Identities()
	if got := findTokens(t, other); got.AccessToken != "" || got.RefreshToken != "" {
		t.Fatalf("a wrong key leaked or returned ciphertext: %+v", got)
	}
	unkeyed := pg.New(db).Identities()
	if got := findTokens(t, unkeyed); got.AccessToken != "" || got.RefreshToken != "" {
		t.Fatalf("no key returned ciphertext: %+v", got)
	}
}

func TestResealMigratesPlaintextAndIsIdempotent(t *testing.T) {
	ids, db, userID := sealedFixture(t, nil)
	saveTokens(t, ids, userID, "at", "rt")
	sealed := pg.New(db, pg.WithTokenSealer(mustSealer(t, secret(1)))).Identities()
	ctx := context.Background()
	if n, err := sealed.ResealIdentities(ctx); err != nil || n != 1 {
		t.Fatalf("first reseal = %d, %v", n, err)
	}
	if access, _ := rawTokens(t, db); !strings.HasPrefix(access, "pv1:") {
		t.Fatalf("still plaintext: %q", access)
	}
	before, _ := rawTokens(t, db)
	if n, err := sealed.ResealIdentities(ctx); err != nil || n != 0 {
		t.Fatalf("second reseal = %d, %v", n, err)
	}
	if after, _ := rawTokens(t, db); after != before {
		t.Fatal("an idempotent reseal rewrote the ciphertext")
	}
	if got := findTokens(t, sealed); got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Fatalf("after reseal = %+v", got)
	}
}

func TestResealRotatesToTheNewestKeyAndSkipsUnreadableRows(t *testing.T) {
	ids, db, userID := sealedFixture(t, mustSealer(t, secret(1)))
	saveTokens(t, ids, userID, "at", "rt")
	ctx := context.Background()
	stranger := pg.New(db, pg.WithTokenSealer(mustSealer(t, secret(9)))).Identities()
	if n, err := stranger.ResealIdentities(ctx); err != nil || n != 0 {
		t.Fatalf("unreadable row touched: %d, %v", n, err)
	}
	rotated := pg.New(db, pg.WithTokenSealer(mustSealer(t, secret(2), secret(1)))).Identities()
	if n, err := rotated.ResealIdentities(ctx); err != nil || n != 1 {
		t.Fatalf("rotation reseal = %d, %v", n, err)
	}
	onlyNew := pg.New(db, pg.WithTokenSealer(mustSealer(t, secret(2)))).Identities()
	if got := findTokens(t, onlyNew); got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Fatalf("new key alone = %+v", got)
	}
}

func TestResealWithoutASealerIsAnError(t *testing.T) {
	ids, _, _ := sealedFixture(t, nil)
	if _, err := ids.ResealIdentities(context.Background()); err == nil {
		t.Fatal("reseal without a sealer succeeded")
	}
}
