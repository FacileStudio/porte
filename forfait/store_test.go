package forfait

import (
	"encoding/json"
	"testing"

	"github.com/FacileStudio/porte/directory"
)

// features is the catalogue every test declares, at the Solo defaults.
func features() []Feature {
	return []Feature{
		{Key: "nuage.storage_gb", Kind: Limit, Default: json.RawMessage(`5`)},
		{Key: "courrier.mailboxes", Kind: Limit, Default: json.RawMessage(`1`)},
		{Key: "glouton.access", Kind: Bool, Default: json.RawMessage(`false`)},
		{Key: "echo.recording", Kind: Bool, Default: json.RawMessage(`false`)},
	}
}

// raw builds one scope's entitlements from JSON literals.
func raw(values map[string]string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(values))
	for key, literal := range values {
		out[key] = json.RawMessage(literal)
	}
	return out
}

// applied is a Store holding one space, "pro", and one person, "u1".
func applied(space, person map[string]string) *Store {
	store := NewStore(features()...)
	store.Apply(directory.Snapshot{
		Version:              1,
		EntitlementsRevision: 1,
		Spaces:               []directory.Space{{ID: "pro", Entitlements: raw(space)}},
		People:               []directory.Person{{Subject: "u1", Entitlements: raw(person)}},
	})
	return store
}

// TestFailOpenBeforeTheFirstSnapshot pins that a Store that never saw
// entitlements allows every declared feature, and still denies undeclared ones.
func TestFailOpenBeforeTheFirstSnapshot(t *testing.T) {
	store := NewStore(features()...)
	store.Apply(directory.Snapshot{Version: 1, Spaces: []directory.Space{{ID: "pro"}}})
	sc := Scope{SpaceID: "pro"}
	if !store.Enabled(sc, "glouton.access") || store.Limit(sc, "nuage.storage_gb") != -1 {
		t.Error("a store with no entitlements snapshot did not fail open")
	}
	if err := store.Check(sc, "nuage.storage_gb", 1<<40, 1<<40); err != nil {
		t.Errorf("Check failed closed before the first snapshot: %v", err)
	}
	if store.Enabled(sc, "nope.key") || store.Limit(sc, "glouton.access") != 0 {
		t.Error("an undeclared or mistyped key did not answer the zero value")
	}
}

// TestResolution walks every source a value can come from after a snapshot.
func TestResolution(t *testing.T) {
	store := applied(
		map[string]string{"nuage.storage_gb": "100", "glouton.access": "true", "courrier.mailboxes": "-1"},
		map[string]string{"nuage.storage_gb": "500", "echo.recording": "true"},
	)
	limits := []struct {
		name  string
		scope Scope
		key   string
		want  int64
	}{
		{"space value", Scope{SpaceID: "pro"}, "nuage.storage_gb", 100},
		{"unlimited", Scope{SpaceID: "pro"}, "courrier.mailboxes", -1},
		{"personal value", Scope{Subject: "u1"}, "nuage.storage_gb", 500},
		{"personal default", Scope{Subject: "u1"}, "courrier.mailboxes", 1},
		{"unknown space default", Scope{SpaceID: "gone"}, "nuage.storage_gb", 5},
		{"unknown person default", Scope{Subject: "u2"}, "nuage.storage_gb", 5},
		{"subject ignored in a space", Scope{SpaceID: "pro", Subject: "u1"}, "nuage.storage_gb", 100},
		{"undeclared", Scope{SpaceID: "pro"}, "nuage.other", 0},
	}
	for _, c := range limits {
		if got := store.Limit(c.scope, c.key); got != c.want {
			t.Errorf("%s: Limit = %d, want %d", c.name, got, c.want)
		}
	}
	if !store.Enabled(Scope{SpaceID: "pro"}, "glouton.access") || store.Enabled(Scope{Subject: "u1"}, "glouton.access") {
		t.Error("glouton.access did not resolve per scope")
	}
	if !store.Enabled(Scope{Subject: "u1"}, "echo.recording") || store.Enabled(Scope{SpaceID: "pro"}, "echo.recording") {
		t.Error("echo.recording did not resolve per scope")
	}
}

// TestLaterSnapshotsAreTheWholeTruth pins that once entitlements arrived, a
// snapshot without them resets every scope to its defaults.
func TestLaterSnapshotsAreTheWholeTruth(t *testing.T) {
	store := applied(map[string]string{"glouton.access": "true"}, nil)
	store.Apply(directory.Snapshot{Version: 2, EntitlementsRevision: 2, Spaces: []directory.Space{{ID: "pro"}}})
	if store.Enabled(Scope{SpaceID: "pro"}, "glouton.access") {
		t.Error("a cleared space kept its paid value")
	}
}

// TestOnlyTheRevisionEndsFailOpen pins the contract signal: entitlements in a
// snapshot with revision 0 are not authoritative, however they look.
func TestOnlyTheRevisionEndsFailOpen(t *testing.T) {
	store := NewStore(features()...)
	store.Apply(directory.Snapshot{Version: 3, Spaces: []directory.Space{
		{ID: "pro", Entitlements: raw(map[string]string{"nuage.storage_gb": "1"})},
	}, People: []directory.Person{{Subject: "u1"}}})
	if store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb") != -1 {
		t.Fatal("a snapshot with revision 0 ended the fail-open period")
	}
	store.Apply(directory.Snapshot{Version: 4, EntitlementsRevision: 1, Spaces: []directory.Space{{ID: "pro"}}})
	if store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb") != 5 {
		t.Error("revision 1 with no values did not read the defaults")
	}
}

// TestAnOlderSnapshotIsIgnored pins the ordering guard on both counters.
func TestAnOlderSnapshotIsIgnored(t *testing.T) {
	store := NewStore(features()...)
	at := func(version, revision int64, gb string) {
		store.Apply(directory.Snapshot{Version: version, EntitlementsRevision: revision, Spaces: []directory.Space{
			{ID: "pro", Entitlements: raw(map[string]string{"nuage.storage_gb": gb})},
		}})
	}
	steps := []struct {
		version, revision int64
		gb                string
		want              int64
	}{
		{10, 5, "100", 100}, {9, 6, "1", 1}, {11, 4, "2", 1}, {11, 0, "3", 1},
		{8, 6, "4", 1}, {0, 6, "5", 5}, {12, 6, "500", 500}, {12, 7, "-1", -1},
	}
	for _, step := range steps {
		at(step.version, step.revision, step.gb)
		if got := store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != step.want {
			t.Errorf("after version %d revision %d: Limit = %d, want %d", step.version, step.revision, got, step.want)
		}
	}
}
