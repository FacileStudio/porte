package pg_test

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
)

// TestSaveFollowsItsThreeRules: insert when absent, never a second subject of
// one provider on an account, never a re-point.
func TestSaveFollowsItsThreeRules(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	u, _ := store.Users().CreateFromPassword(ctx, "save@example.test", "S")
	v, _ := store.Users().CreateFromPassword(ctx, "other@example.test", "O")
	steps := []struct {
		identity porte.StoredIdentity
		want     error
	}{
		{porte.StoredIdentity{UserID: u, Provider: "https://sso.test", Subject: "first"}, nil},
		{porte.StoredIdentity{UserID: u, Provider: "https://sso.test", Subject: "second"}, porte.ErrNotFound},
		{porte.StoredIdentity{UserID: u, Provider: "https://other.idp", Subject: "x"}, nil},
		{porte.StoredIdentity{UserID: v, Provider: "https://sso.test", Subject: "first"}, porte.ErrNotFound},
	}
	for i, step := range steps {
		if err := store.Identities().Save(ctx, step.identity); !stderrors.Is(err, step.want) || (step.want == nil) != (err == nil) {
			t.Errorf("step %d: Save = %v, want %v", i, err, step.want)
		}
	}
	if got, _ := store.Identities().Find(ctx, "https://sso.test", "first"); got.UserID != u {
		t.Fatalf("first was re-pointed to %d", got.UserID)
	}
}

// squatterSession plants one live session on a row, as its holder's login
// would have, and returns its id.
func squatterSession(t *testing.T, store *pg.Store, userID int64, hash string) int64 {
	t.Helper()
	created, err := store.Sessions().Create(context.Background(), porte.Session{
		UserID: userID, TokenHash: hash, CreatedAt: time.Now(), LastUsedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("plant: %v", err)
	}
	return created.ID
}

// raceAgainstEviction runs every write alongside the owner's verified login
// and reports how many sessions are left on the row afterwards.
func raceAgainstEviction(t *testing.T, db *sql.DB, row int64, evict func(), writes ...func()) int {
	t.Helper()
	var wg sync.WaitGroup
	for _, write := range append(writes, evict) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			write()
		}()
	}
	wg.Wait()
	var left int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM porte_sessions WHERE user_id = $1`, row).Scan(&left); err != nil {
		t.Fatalf("count: %v", err)
	}
	return left
}

// evictor is the owner's verified login, as one racing write.
func evictor(store *pg.Store, owner porte.Claims) func() {
	return func() { _, _ = store.Users().UpsertFromOIDC(context.Background(), owner) }
}

// TestNothingTheSquatterIssuesSurvivesTheEviction: a federated squatter's
// bound login, its API-token loop and a late Save all race the owner's
// login. Whatever order they land in, the row ends with no session and no
// squatter identity.
func TestNothingTheSquatterIssuesSurvivesTheEviction(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	for i := range 30 {
		email := fmt.Sprintf("race%d@example.test", i)
		row, err := store.Users().UpsertFromOIDC(ctx, claims("att"+email, email, false))
		if err != nil {
			t.Fatalf("squat %d: %v", i, err)
		}
		parent := squatterSession(t, store, row, "p"+email)
		session := func(hash string, template porte.Session) func() {
			return func() {
				template.TokenHash, template.UserID, template.CreatedAt, template.LastUsedAt = hash, row, time.Now(), time.Now()
				_, _ = store.Sessions().Create(ctx, template)
			}
		}
		late := func() {
			_ = store.Identities().Save(ctx, porte.StoredIdentity{UserID: row, Provider: "https://sso.test", Subject: "att" + email})
		}
		left := raceAgainstEviction(t, db, row, evictor(store, claims("vic"+email, email, true)),
			session("b"+email, porte.Session{Provider: "https://sso.test", Subject: "att" + email}),
			session("t"+email, porte.Session{Label: "token", IssuedBy: parent}),
			late)
		if left != 0 || identityCount(t, db, row, "att"+email) != 0 {
			t.Fatalf("iteration %d: %d sessions and %d squatter identities survived", i, left, identityCount(t, db, row, "att"+email))
		}
	}
}

// TestNothingAPasswordSquatterIssuesSurvivesTheEviction: the CustomerAccounts
// case. A password-registered squatter's login and token loop race the
// owner's first verified login.
func TestNothingAPasswordSquatterIssuesSurvivesTheEviction(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	for i := range 30 {
		email := fmt.Sprintf("pw%d@example.test", i)
		row, err := store.Users().CreateFromPassword(ctx, email, "Squatter")
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		local := porte.StoredIdentity{UserID: row, Provider: porte.ProviderLocal, Subject: porte.LocalSubject(row), PasswordHash: "x"}
		if err := store.Identities().Save(ctx, local); err != nil {
			t.Fatalf("password %d: %v", i, err)
		}
		parent := squatterSession(t, store, row, "p"+email)
		login := func() {
			_, _ = store.Sessions().Create(ctx, porte.Session{UserID: row, TokenHash: "l" + email, CreatedAt: time.Now(), LastUsedAt: time.Now(),
				Provider: porte.ProviderLocal, Subject: porte.LocalSubject(row)})
		}
		token := func() {
			_, _ = store.Sessions().Create(ctx, porte.Session{UserID: row, TokenHash: "t" + email, CreatedAt: time.Now(), LastUsedAt: time.Now(),
				Label: "token", IssuedBy: parent})
		}
		if left := raceAgainstEviction(t, db, row, evictor(store, claims("vic"+email, email, true)), login, token); left != 0 {
			t.Fatalf("iteration %d: %d of the squatter's sessions survived", i, left)
		}
	}
}
