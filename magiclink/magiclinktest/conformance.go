package magiclinktest

import (
	"context"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

// Conformance runs the contract of porte.MagicLinkStore against an implementation.
// newStore must return an empty store, and newUser a user id the store accepts
// (a store with a foreign key needs a real row); each subtest gets a fresh store.
//
// It asserts the five things whose drift is a security bug: a link is spent
// once even under contention, every dead link answers the same way, a new link
// ends the older ones atomically, the counts see spent links, and the sweep
// keeps what the limits still need.
func Conformance(t *testing.T, newStore func(t *testing.T) porte.MagicLinkStore, newUser func(t *testing.T) int64) {
	t.Helper()
	run := func(name string, test func(*testing.T, porte.MagicLinkStore, func(*testing.T) int64)) {
		t.Run(name, func(t *testing.T) { test(t, newStore(t), newUser) })
	}
	run("a link is spent once", testSingleUse)
	run("a dead link is one answer", testUniformFailure)
	run("a link expires at its deadline", testExpiry)
	run("a new link ends the older ones", testSupersession)
	run("concurrent consumes have one winner", testConcurrentConsume)
	run("concurrent creates leave one live link", testConcurrentCreate)
	run("counts see spent links and respect their key", testCounts)
	run("the sweep keeps what is live", testSweep)
}

func testSingleUse(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	user := newUser(t)
	mustCreate(t, store, link(user, "h1", "", epoch))
	got, err := store.Consume(context.Background(), "h1", epoch.Add(time.Minute))
	if err != nil || got != user {
		t.Fatalf("first consume: got (%d, %v), want (%d, nil)", got, err, user)
	}
	wantDead(t, store, "h1", epoch.Add(2*time.Minute))
}

func testUniformFailure(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	user := newUser(t)
	mustCreate(t, store, link(user, "spent", "", epoch))
	mustCreate(t, store, link(user, "live", "", epoch))
	wantDead(t, store, "spent", epoch)
	wantDead(t, store, "unknown", epoch)
	wantDead(t, store, "live", epoch.Add(ttl+time.Second))
}

func testExpiry(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	user := newUser(t)
	mustCreate(t, store, link(user, "edge", "", epoch))
	wantDead(t, store, "edge", epoch.Add(ttl))
	mustCreate(t, store, link(user, "inside", "", epoch))
	if _, err := store.Consume(context.Background(), "inside", epoch.Add(ttl-time.Second)); err != nil {
		t.Fatalf("a link one second before its deadline must work: %v", err)
	}
}

func testSupersession(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	first, second := newUser(t), newUser(t)
	mustCreate(t, store, link(first, "old", "", epoch))
	mustCreate(t, store, link(second, "other", "", epoch))
	mustCreate(t, store, link(first, "new", "", epoch.Add(time.Minute)))
	wantDead(t, store, "old", epoch.Add(2*time.Minute))
	if _, err := store.Consume(context.Background(), "new", epoch.Add(2*time.Minute)); err != nil {
		t.Fatalf("the newest link must work: %v", err)
	}
	if _, err := store.Consume(context.Background(), "other", epoch.Add(2*time.Minute)); err != nil {
		t.Fatalf("another user's link must survive: %v", err)
	}
}

func testCounts(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	first, second := newUser(t), newUser(t)
	mustCreate(t, store, link(first, "a", "10.0.0.1", epoch))
	mustCreate(t, store, link(first, "b", "10.0.0.2", epoch.Add(time.Minute)))
	mustCreate(t, store, link(second, "c", "10.0.0.1", epoch.Add(2*time.Minute)))
	if _, err := store.Consume(context.Background(), "b", epoch.Add(3*time.Minute)); err != nil {
		t.Fatalf("consume b: %v", err)
	}
	cases := []struct {
		name  string
		key   porte.LinkKey
		since time.Time
		want  int
	}{
		{"by user, spent and superseded included", porte.LinkKey{UserID: first}, epoch, 2},
		{"by ip", porte.LinkKey{IP: "10.0.0.1"}, epoch, 2},
		{"by both", porte.LinkKey{UserID: first, IP: "10.0.0.1"}, epoch, 1},
		{"since is inclusive", porte.LinkKey{UserID: first}, epoch.Add(time.Minute), 1},
		{"since excludes older", porte.LinkKey{UserID: first}, epoch.Add(time.Hour), 0},
		{"a zero key matches nothing", porte.LinkKey{}, epoch, 0},
	}
	for _, tc := range cases {
		got, err := store.CountSince(context.Background(), tc.key, tc.since)
		if err != nil || got != tc.want {
			t.Errorf("%s: got (%d, %v), want %d", tc.name, got, err, tc.want)
		}
	}
}

func testSweep(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	user := newUser(t)
	other := newUser(t)
	mustCreate(t, store, link(user, "stale", "", epoch))
	mustCreate(t, store, link(other, "live", "", epoch.Add(time.Hour)))
	removed, err := store.DeleteExpired(context.Background(), epoch.Add(30*time.Minute))
	if err != nil || removed != 1 {
		t.Fatalf("sweep: got (%d, %v), want (1, nil)", removed, err)
	}
	if _, err := store.Consume(context.Background(), "live", epoch.Add(time.Hour+time.Minute)); err != nil {
		t.Fatalf("the sweep removed a live link: %v", err)
	}
	if got, _ := store.CountSince(context.Background(), porte.LinkKey{UserID: user}, epoch); got != 0 {
		t.Fatalf("the swept link is still counted: %d", got)
	}
}
