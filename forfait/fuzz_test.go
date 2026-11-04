package forfait

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/FacileStudio/porte/directory"
)

// FuzzApply decodes arbitrary bytes as a snapshot, applies it and reads every
// feature. Nothing may panic, and every limit stays in the legal domain.
func FuzzApply(f *testing.F) {
	seeds := []string{
		`{"version":1,"entitlements_revision":1,"spaces":[{"id":"a","entitlements":{"nuage.storage_gb":100,"glouton.access":true}}]}`,
		`{"version":-5,"entitlements_revision":-1,"spaces":[{"id":"a","entitlements":{"nuage.storage_gb":1}}]}`,
		`{"spaces":[{"id":"a","entitlements":{"nuage.storage_gb":null,"glouton.access":"x"}}],"people":[{"sub":""}]}`,
		`{"people":[{"sub":"u","entitlements":{"nuage.storage_gb":-9223372036854775808}}]}`,
		`{"people":[{"sub":"u","entitlements":{"nuage.storage_gb":1e400,"glouton.access":[true]}}]}`,
		`{"spaces":[{"id":"","entitlements":{}},{"id":"","entitlements":{"courrier.mailboxes":-1}}]}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var snap directory.Snapshot
		if json.Unmarshal(body, &snap) != nil {
			return
		}
		store := NewStore(features()...)
		store.Apply(snap)
		for _, sc := range scopesOf(snap) {
			readEvery(t, store, sc)
		}
	})
}

// readEvery reads each feature for sc and fails on an illegal answer.
func readEvery(t *testing.T, store *Store, sc Scope) {
	for _, feature := range features() {
		if limit := store.Limit(sc, feature.Key); limit < -1 {
			t.Fatalf("Limit(%+v, %s) = %d", sc, feature.Key, limit)
		}
		store.Enabled(sc, feature.Key)
		if err := store.Check(sc, feature.Key, 1, 1); err != nil && !errors.Is(err, ErrLimit) {
			t.Fatalf("Check(%+v, %s) = %v", sc, feature.Key, err)
		}
	}
}

// scopesOf lists every scope a snapshot names.
func scopesOf(snap directory.Snapshot) []Scope {
	scopes := []Scope{{}}
	for _, space := range snap.Spaces {
		scopes = append(scopes, Scope{SpaceID: space.ID})
	}
	for _, person := range snap.People {
		scopes = append(scopes, Scope{Subject: person.Subject})
	}
	return scopes
}

// TestConcurrentApplyAndReads is for the race detector: snapshots and reads
// interleave freely.
func TestConcurrentApplyAndReads(t *testing.T) {
	store := NewStore(features()...)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go applyMany(&wg, store)
		go readMany(&wg, store, Scope{SpaceID: "pro", Subject: string(rune('a' + i))})
	}
	wg.Wait()
	if got := store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 100 {
		t.Errorf("after the race, Limit = %d, want 100", got)
	}
}

// applyMany applies 200 snapshots in a row.
func applyMany(wg *sync.WaitGroup, store *Store) {
	defer wg.Done()
	space := directory.Space{ID: "pro", Entitlements: raw(map[string]string{"nuage.storage_gb": "100"})}
	for v := range 200 {
		store.Apply(directory.Snapshot{Version: int64(v), EntitlementsRevision: 1, Spaces: []directory.Space{space}})
	}
}

// readMany reads one scope 200 times in a row.
func readMany(wg *sync.WaitGroup, store *Store, sc Scope) {
	defer wg.Done()
	for range 200 {
		store.Limit(sc, "nuage.storage_gb")
		store.Enabled(sc, "glouton.access")
	}
}
