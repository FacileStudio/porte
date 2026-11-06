package forfait

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/directory"
)

// snapshotAt is one space "pro" with a storage limit, at the given versions.
func snapshotAt(version, revision int64, gb string) directory.Snapshot {
	return directory.Snapshot{Version: version, EntitlementsRevision: revision, Spaces: []directory.Space{
		{ID: "pro", Entitlements: raw(map[string]string{"nuage.storage_gb": gb})},
	}}
}

// TestARestoredRegistreStillDeliversUpgrades is the reviewer's case: the
// directory version went back with a restore, but the revision moved on.
func TestARestoredRegistreStillDeliversUpgrades(t *testing.T) {
	store := NewStore(features()...)
	store.Apply(snapshotAt(900, 40, "100"))
	store.Apply(snapshotAt(850, 41, "500"))
	if got := store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 500 {
		t.Fatalf("Limit = %d, want the upgrade to 500", got)
	}
}

// TestARefusedSnapshotIsLoggedAndResetRecovers: a revision that went back is
// refused loudly, and Reset makes the next snapshot apply, including after a
// restart that imported the stale state.
func TestARefusedSnapshotIsLoggedAndResetRecovers(t *testing.T) {
	var logs bytes.Buffer
	store := NewStore(features()...)
	store.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	store.Apply(snapshotAt(900, 40, "100"))
	store.Apply(snapshotAt(10, 3, "500"))
	if got := store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 100 {
		t.Fatalf("a lower revision was applied: %d", got)
	}
	for _, want := range []string{"revision=3", "held_revision=40", "held_version=900", "Reset"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the refusal log lacks %q: %s", want, logs.String())
		}
	}
	restartAndReset(t, store)
}

// restartAndReset carries the stale state across a restart, then recovers
// with Reset and checks the restored Registre's snapshot now applies.
func restartAndReset(t *testing.T, store *Store) {
	t.Helper()
	saved, err := store.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	restarted := NewStore(features()...)
	if err := restarted.Import(saved); err != nil {
		t.Fatalf("Import: %v", err)
	}
	restarted.Reset()
	if got := restarted.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != -1 {
		t.Errorf("a reset store does not fail open: %d", got)
	}
	restarted.Apply(snapshotAt(10, 3, "500"))
	if got := restarted.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 500 {
		t.Errorf("after Reset the restored Registre's snapshot was refused: %d", got)
	}
}

// TestImportOfNothingIsANoOpAndASecondImportIsTyped pins the two documented
// answers an app branches on.
func TestImportOfNothingIsANoOpAndASecondImportIsTyped(t *testing.T) {
	store := NewStore(features()...)
	for _, empty := range [][]byte{nil, {}, []byte(" \n")} {
		if err := store.Import(empty); err != nil {
			t.Errorf("Import(%q) = %v, want nil", empty, err)
		}
	}
	saved, _ := applied(map[string]string{"glouton.access": "true"}, nil).Export()
	store.Apply(snapshotAt(1, 1, "5"))
	if err := store.Import(saved); !errors.Is(err, ErrAlreadyApplied) {
		t.Errorf("Import after Apply = %v, want ErrAlreadyApplied", err)
	}
}

// TestEmptyIdsAreSkipped: a space with no id must not become the scope every
// unlinked lookup lands in.
func TestEmptyIdsAreSkipped(t *testing.T) {
	store := NewStore(features()...)
	store.Apply(directory.Snapshot{EntitlementsRevision: 1, Spaces: []directory.Space{
		{ID: "", Entitlements: raw(map[string]string{"glouton.access": "true"})},
	}, People: []directory.Person{{Subject: "", Entitlements: raw(map[string]string{"glouton.access": "true"})}}})
	if store.Enabled(Scope{}, "glouton.access") {
		t.Error("an empty subject's entitlements reached the empty scope")
	}
}

// TestNewStoreReportsBadDeclarations: each programmer error is logged.
func TestNewStoreReportsBadDeclarations(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	NewStore(Feature{Key: "Bad Key", Kind: Limit}, Feature{Key: "a.b", Kind: Limit})
	if !strings.Contains(logs.String(), "Bad Key") || !strings.Contains(logs.String(), "a.b") {
		t.Errorf("bad declarations went unreported: %s", logs.String())
	}
}
