package pg_test

import (
	"context"
	"testing"

	"github.com/FacileStudio/porte/directory"
)

func TestHoldsIdentityFollowsAnErasureAndARecreation(t *testing.T) {
	store, _ := open(t)
	ctx := context.Background()
	seedPerson(t, store, "alice")
	seedPerson(t, store, "bob")
	_ = directory.Deletions{Holds: store.HoldsIdentity}
	holds := func(subject string) bool {
		t.Helper()
		held, err := store.HoldsIdentity(ctx, "https://sso.test", subject)
		if err != nil {
			t.Fatal(err)
		}
		return held
	}
	if !holds("alice") || holds("nobody") {
		t.Fatal("HoldsIdentity does not see the seeded identity, or sees one that never existed")
	}
	if err := store.EraseIdentity(ctx, "https://sso.test", "alice"); err != nil {
		t.Fatal(err)
	}
	if holds("alice") || !holds("bob") {
		t.Fatal("after the erasure alice is still held, or bob is not")
	}
	if _, err := store.Users().UpsertFromOIDC(ctx, claims("alice", "alice@facile.test", true)); err != nil {
		t.Fatal(err)
	}
	if !holds("alice") {
		t.Fatal("a re-created account is not reported as holding the identity")
	}
}
