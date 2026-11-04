package pg_test

import (
	"context"
	"database/sql"
	stderrors "errors"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

// squatThenEvict runs the losing order of the race step by step: the
// unverified holder's upsert commits, then the owner's verified login purges
// it. It returns the shared row and the purged holder's subject.
func squatThenEvict(t *testing.T, users porte.UserStore) (int64, porte.Session) {
	t.Helper()
	ctx := context.Background()
	held, err := users.UpsertFromOIDC(ctx, claims("sub-att", "victim@example.test", false))
	if err != nil {
		t.Fatalf("squat: %v", err)
	}
	owner, err := users.UpsertFromOIDC(ctx, claims("sub-vic", "victim@example.test", true))
	if err != nil || owner != held {
		t.Fatalf("owner landed on %d (row %d): %v", owner, held, err)
	}
	return owner, porte.Session{UserID: held, Provider: "https://sso.test", Subject: "sub-att"}
}

// TestAPurgedLoginGetsNoSessionCodeOrIdentity: upsert, then purge, then the
// purged login's session, code and identity write all fail and leave nothing.
func TestAPurgedLoginGetsNoSessionCodeOrIdentity(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	owner, stale := squatThenEvict(t, store.Users())
	stale.TokenHash, stale.CreatedAt, stale.LastUsedAt = porte.HashToken("late"), time.Now(), time.Now()
	if _, err := store.Sessions().Create(ctx, stale); !stderrors.Is(err, porte.ErrNotFound) {
		t.Errorf("the purged login was issued a session: %v", err)
	}
	code := porte.LoginCode{CodeHash: "late-code", UserID: owner, ExpiresAt: time.Now().Add(time.Minute), Provider: stale.Provider, Subject: stale.Subject}
	if err := store.LoginCodes().Create(ctx, code); !stderrors.Is(err, porte.ErrNotFound) {
		t.Errorf("the purged login was issued a login code: %v", err)
	}
	if err := store.Identities().Save(ctx, porte.StoredIdentity{UserID: owner, Provider: stale.Provider, Subject: stale.Subject}); !stderrors.Is(err, porte.ErrNotFound) {
		t.Errorf("a late Save resurrected the purged identity: %v", err)
	}
	if left := leftovers(t, db, owner); len(left) != 0 {
		t.Errorf("rows left on the owner's account: %v", left)
	}
	if got := identitiesOf(t, db, owner); len(got) != 1 || got[0] != "https://sso.test:sub-vic" {
		t.Errorf("identities on the owner's account: %v", got)
	}
}

// TestABoundSessionStillIssuesWhileItsIdentityExists: the guard does not get
// in the way of the ordinary login, nor of an unbound session.
func TestABoundSessionStillIssuesWhileItsIdentityExists(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	owner, err := store.Users().UpsertFromOIDC(ctx, claims("sub-1", "camille@example.test", true))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	for _, s := range []porte.Session{
		{UserID: owner, TokenHash: "bound", Provider: "https://sso.test", Subject: "sub-1"},
		{UserID: owner, TokenHash: "unbound"},
	} {
		s.CreatedAt, s.LastUsedAt = time.Now(), time.Now()
		if _, err := store.Sessions().Create(ctx, s); err != nil {
			t.Errorf("%s session refused: %v", s.TokenHash, err)
		}
	}
	other := porte.Session{UserID: owner + 1000, TokenHash: "wrong-user", Provider: "https://sso.test", Subject: "sub-1", CreatedAt: time.Now(), LastUsedAt: time.Now()}
	if _, err := store.Sessions().Create(ctx, other); !stderrors.Is(err, porte.ErrNotFound) {
		t.Errorf("a session bound to another user's identity was stored: %v", err)
	}
}

// TestASessionInsertWaitsForAnInFlightPurge holds a purge open, as
// UpsertFromOIDC runs it (user row FOR UPDATE, then the deletes), starts the
// bound insert, proves it is blocked on the user row, then commits the
// purge: the insert must store nothing.
func TestASessionInsertWaitsForAnInFlightPurge(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	owner, err := store.Users().UpsertFromOIDC(ctx, claims("sub-att", "victim@example.test", false))
	if err != nil {
		t.Fatalf("squat: %v", err)
	}
	purge, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = purge.Rollback() }()
	for _, statement := range []string{
		`SELECT 1 FROM porte_users WHERE id = $1 FOR UPDATE`,
		`DELETE FROM porte_identities WHERE user_id = $1`,
	} {
		if _, err := purge.ExecContext(ctx, statement, owner); err != nil {
			t.Fatalf("purge: %v", err)
		}
	}
	done := createAsync(store.Sessions(), porte.Session{
		UserID: owner, TokenHash: "racing", Provider: "https://sso.test", Subject: "sub-att",
		CreatedAt: time.Now(), LastUsedAt: time.Now(),
	})
	waitForLockWait(t, db)
	if err := purge.Commit(); err != nil {
		t.Fatalf("commit purge: %v", err)
	}
	if err := <-done; !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("the racing session insert = %v, want ErrNotFound", err)
	}
}

// createAsync starts one session insert and reports its error when done.
func createAsync(sessions porte.SessionStore, session porte.Session) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := sessions.Create(context.Background(), session)
		done <- err
	}()
	return done
}

// waitForLockWait returns once some backend is waiting on a row lock.
func waitForLockWait(t *testing.T, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := db.QueryRowContext(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`).Scan(&waiting); err != nil {
			t.Fatalf("pg_stat_activity: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the session insert never waited on the purge")
}
