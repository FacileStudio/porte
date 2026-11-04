package pg_test

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
)

// raceUpserts runs every claim's first login at once.
func raceUpserts(users porte.UserStore, all ...porte.Claims) ([]int64, []error) {
	ids := make([]int64, len(all))
	errs := make([]error, len(all))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ids[i], errs[i] = users.UpsertFromOIDC(context.Background(), c)
		}()
	}
	close(start)
	wg.Wait()
	return ids, errs
}

// TestConcurrentUnverifiedLoginsOfOneSubjectResolveToOneUser: the loser of an
// unverified race finds the winner by subject, never by email.
func TestConcurrentUnverifiedLoginsOfOneSubjectResolveToOneUser(t *testing.T) {
	store, _ := open(t)
	all := make([]porte.Claims, 8)
	for i := range all {
		all[i] = claims("s1", "u@example.test", false)
	}
	ids, errs := raceUpserts(store.Users(), all...)
	for i, err := range errs {
		if err != nil || ids[i] != ids[0] {
			t.Fatalf("racer %d: id %d err %v, want %d", i, ids[i], err, ids[0])
		}
	}
}

// TestAnUnverifiedRacerNeverJoinsAVerifiedOne: two subjects, one address, one
// of them unverified. They must not end up as one account.
func TestAnUnverifiedRacerNeverJoinsAVerifiedOne(t *testing.T) {
	store, _ := open(t)
	ids, errs := raceUpserts(store.Users(), claims("s1", "m@example.test", true), claims("s2", "m@example.test", false))
	if errs[0] == nil && errs[1] == nil && ids[0] == ids[1] {
		t.Fatalf("the unverified racer linked into the verified racer's user %d", ids[0])
	}
}

// TestAVerifiedLoginPurgesAPreRegisteredRow: a stranger registers the
// victim's address with a password, then the victim signs in through the
// issuer. The stranger's password, sessions and tokens must not survive.
func TestAVerifiedLoginPurgesAPreRegisteredRow(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	squatter, err := store.Users().CreateFromPassword(ctx, "victim@example.test", "Attacker")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Identities().Save(ctx, porte.StoredIdentity{
		UserID: squatter, Provider: porte.ProviderLocal, Subject: porte.LocalSubject(squatter), PasswordHash: "x",
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	session := porte.Session{UserID: squatter, TokenHash: porte.HashToken("squatter-token"), Label: "api"}
	if _, err := store.Sessions().Create(ctx, session); err != nil {
		t.Fatalf("session: %v", err)
	}
	victim, err := store.Users().UpsertFromOIDC(ctx, claims("victim-sub", "victim@example.test", true))
	if err != nil {
		t.Fatalf("victim login: %v", err)
	}
	if _, err := store.Identities().Find(ctx, porte.ProviderLocal, porte.LocalSubject(victim)); !stderrors.Is(err, porte.ErrNotFound) {
		t.Errorf("the squatter's password survived the victim's login: %v", err)
	}
	if _, err := store.Sessions().Find(ctx, session.TokenHash); !stderrors.Is(err, porte.ErrNotFound) {
		t.Errorf("the squatter's token survived the victim's login: %v", err)
	}
}

// TestARecycledAddressIsNotLinked: a second subject of the same issuer with
// an address already linked to the first is somebody else.
func TestARecycledAddressIsNotLinked(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-A", "old@example.test", true)); err != nil {
		t.Fatalf("A: %v", err)
	}
	if b, err := store.Users().UpsertFromOIDC(ctx, claims("sub-B", "old@example.test", true)); err == nil {
		t.Fatalf("sub-B linked into user %d through a recycled address", b)
	}
}

// TestAnUnverifiedClaimCannotSquatAnAddress: an account switching its IdP
// address to someone else's, unverified, must not take that address.
func TestAnUnverifiedClaimCannotSquatAnAddress(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	attacker, err := store.Users().UpsertFromOIDC(ctx, claims("sub-att", "att@example.test", true))
	if err != nil {
		t.Fatalf("attacker: %v", err)
	}
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-att", "victim@example.test", false)); err != nil {
		t.Fatalf("squat attempt: %v", err)
	}
	var email string
	if err := db.QueryRowContext(ctx, `SELECT email FROM porte_users WHERE id = $1`, attacker).Scan(&email); err != nil || email != "att@example.test" {
		t.Fatalf("an unverified claim rewrote the address to %q (%v)", email, err)
	}
	victim, err := store.Users().UpsertFromOIDC(ctx, claims("sub-vic", "victim@example.test", true))
	if err != nil || victim == attacker {
		t.Fatalf("the victim landed on %d (attacker %d): %v", victim, attacker, err)
	}
}

// TestAddressCaseDoesNotSplitOrJoinWrongly: a verified Case@Example.test
// links to a local case@example.test row, under the purge rule.
func TestAddressCaseDoesNotSplitOrJoinWrongly(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	local, err := store.Users().CreateFromPassword(ctx, "case@example.test", "L")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	federated, err := store.Users().UpsertFromOIDC(ctx, claims("sub-c", " Case@Example.TEST ", true))
	if err != nil || federated != local {
		t.Fatalf("federated %d, local %d: %v", federated, local, err)
	}
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("sub-d", "CASE@example.test", true)); err == nil {
		t.Fatal("a second subject linked into the now-federated row through a case variant")
	}
}

// TestAnEmptyAddressIsRefused: no address, no account, rather than every
// address-less subject fighting over one empty-string row.
func TestAnEmptyAddressIsRefused(t *testing.T) {
	store, _ := open(t)
	for _, subject := range []string{"e1", "e2"} {
		if id, err := store.Users().UpsertFromOIDC(context.Background(), claims(subject, "  ", false)); err == nil {
			t.Errorf("subject %s with no address resolved to %d", subject, id)
		}
	}
}

// TestEnsureSchemaDoesNotWaitBehindAReader: with nothing to add, a boot must
// not take the exclusive lock an ALTER TABLE needs.
func TestEnsureSchemaDoesNotWaitBehindAReader(t *testing.T) {
	_, db := open(t)
	ctx := context.Background()
	reader, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = reader.Rollback() }()
	for _, table := range []string{"porte_users", "porte_identities", "porte_login_codes"} {
		if _, err := reader.ExecContext(ctx, "SELECT 1 FROM "+table+" LIMIT 1"); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := pg.EnsureSchema(bounded, db); err != nil {
		t.Fatalf("EnsureSchema queued behind a reader: %v", err)
	}
}
