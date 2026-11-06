package forfait

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/directory"
)

// TestExportImportRoundTrip pins that a restarted Store reads exactly what
// the exporting one applied, and no longer fails open.
func TestExportImportRoundTrip(t *testing.T) {
	before := applied(
		map[string]string{"nuage.storage_gb": "100", "glouton.access": "true", "courrier.mailboxes": "-1"},
		map[string]string{"nuage.storage_gb": "500"},
	)
	document, err := before.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	after := NewStore(features()...)
	if err := after.Import(document); err != nil {
		t.Fatalf("Import: %v", err)
	}
	scopes := []Scope{{SpaceID: "pro"}, {Subject: "u1"}, {SpaceID: "gone"}, {Subject: "u2"}}
	for _, sc := range scopes {
		for _, feature := range features() {
			if before.Limit(sc, feature.Key) != after.Limit(sc, feature.Key) ||
				before.Enabled(sc, feature.Key) != after.Enabled(sc, feature.Key) {
				t.Errorf("%+v %s differs after the round trip", sc, feature.Key)
			}
		}
	}
	if after.Limit(Scope{SpaceID: "gone"}, "nuage.storage_gb") != 5 {
		t.Error("an imported store still failed open")
	}
}

// TestAnUnappliedExportStillFailsOpen pins that the fail-open flag is part of
// the document, both ways.
func TestAnUnappliedExportStillFailsOpen(t *testing.T) {
	document, err := NewStore(features()...).Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	store := NewStore(features()...)
	if err := store.Import(document); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb") != -1 {
		t.Error("importing a fail-open document ended the fail-open period")
	}
}

// TestImportFiltersLikeApply feeds values Apply would drop.
func TestImportFiltersLikeApply(t *testing.T) {
	pad := make([]string, 0, maxKeys)
	for i := range maxKeys {
		pad = append(pad, fmt.Sprintf(`"pad.k%d":1`, i))
	}
	document := `{"version":1,"entitlements_revision":1,"spaces":{` +
		`"pro":{"nuage.storage_gb":-2,"glouton.access":"true","courrier.mailboxes":3,"Bad Key":1},` +
		`"big":{"nuage.storage_gb":900,` + strings.Join(pad, ",") + `}},"people":{"u1":{"nuage.storage_gb":null}}}`
	store := NewStore(features()...)
	if err := store.Import([]byte(document)); err != nil {
		t.Fatalf("Import: %v", err)
	}
	pro, big, person := Scope{SpaceID: "pro"}, Scope{SpaceID: "big"}, Scope{Subject: "u1"}
	if store.Limit(pro, "nuage.storage_gb") != 5 || store.Enabled(pro, "glouton.access") ||
		store.Limit(pro, "courrier.mailboxes") != 3 {
		t.Error("Import did not filter the values Apply drops")
	}
	if store.Limit(big, "nuage.storage_gb") != 5 || store.Limit(person, "nuage.storage_gb") != 5 {
		t.Error("an oversized scope or a null value survived Import")
	}
}

// TestImportRejects walks every document Import must refuse, leaving the
// Store failing open.
func TestImportRejects(t *testing.T) {
	documents := map[string]string{
		"garbage":           `{"version":`,
		"not an object":     `[1]`,
		"no version":        `{"entitlements_revision":1}`,
		"future version":    `{"version":2,"entitlements_revision":1}`,
		"unknown field":     `{"version":1,"entitlements_revision":1,"plan":"studio"}`,
		"trailing data":     `{"version":1,"entitlements_revision":1} {}`,
		"negative revision": `{"version":1,"entitlements_revision":-1}`,
		"negative snapshot": `{"version":1,"snapshot_version":-1,"entitlements_revision":1}`,
		"wrong types":       `{"version":1,"entitlements_revision":1,"spaces":{"pro":[true]}}`,
		"oversized input":   `{"version":1,"entitlements_revision":1,"spaces":{}}` + strings.Repeat(" ", maxExport),
	}
	for name, document := range documents {
		store := NewStore(features()...)
		if err := store.Import([]byte(document)); err == nil {
			t.Errorf("%s: Import accepted it", name)
		}
		if store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb") != -1 {
			t.Errorf("%s: a refused Import changed the Store", name)
		}
	}
}

// TestImportNeverOverwritesAnAppliedSnapshot pins that a stale saved document
// cannot replace what Registre already served this process.
func TestImportNeverOverwritesAnAppliedSnapshot(t *testing.T) {
	stale, err := applied(map[string]string{"glouton.access": "true"}, nil).Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	store := applied(map[string]string{"glouton.access": "false"}, nil)
	if store.Import(stale) == nil || store.Enabled(Scope{SpaceID: "pro"}, "glouton.access") {
		t.Error("Import replaced a snapshot this process applied")
	}
}

// FuzzImport feeds arbitrary bytes to Import. Nothing may panic, every limit
// stays legal, and an accepted document exports and imports again.
func FuzzImport(f *testing.F) {
	seeds := []string{
		`{"version":1,"entitlements_revision":1,"spaces":{"pro":{"nuage.storage_gb":100}},"people":{"u":{"glouton.access":true}}}`,
		`{"version":1,"entitlements_revision":0}`,
		`{"version":1,"entitlements_revision":1,"spaces":{"":{"nuage.storage_gb":-9223372036854775808}},"people":null}`,
		`{"version":1,"entitlements_revision":1,"spaces":{"a":null,"b":{"glouton.access":1e999}}}`,
		`{"version":0}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		store := NewStore(features()...)
		if store.Import(body) != nil {
			return
		}
		snap := directory.Snapshot{Spaces: []directory.Space{{ID: "pro"}, {ID: "a"}}, People: []directory.Person{{Subject: "u"}}}
		for _, sc := range scopesOf(snap) {
			readEvery(t, store, sc)
		}
		reexported, err := store.Export()
		if err != nil || NewStore(features()...).Import(reexported) != nil || !json.Valid(reexported) {
			t.Fatalf("an accepted document did not round-trip: %v", err)
		}
	})
}

// TestImportedStateGuardsApply pins that a restored Store refuses a snapshot
// older than the one it exported from.
func TestImportedStateGuardsApply(t *testing.T) {
	before := NewStore(features()...)
	before.Apply(directory.Snapshot{Version: 40, EntitlementsRevision: 9, Spaces: []directory.Space{
		{ID: "pro", Entitlements: raw(map[string]string{"nuage.storage_gb": "100"})},
	}})
	document, err := before.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	after := NewStore(features()...)
	if err := after.Import(document); err != nil {
		t.Fatalf("Import: %v", err)
	}
	stale := []directory.Snapshot{{Version: 39, EntitlementsRevision: 9}, {Version: 41, EntitlementsRevision: 8}}
	for _, snap := range stale {
		after.Apply(snap)
		if got := after.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 100 {
			t.Errorf("stale snapshot %+v replaced the imported state: Limit = %d", snap, got)
		}
	}
}

// TestASnapshotAtTheCapRoundTrips pins that Import's cap admits whatever
// Export makes from the largest snapshot Client reads, built from the worst
// case for re-encoding: space ids of raw invalid UTF-8, each byte of which
// decodes to a three-byte U+FFFD.
func TestASnapshotAtTheCapRoundTrips(t *testing.T) {
	values := `{"nuage.storage_gb":-1,"courrier.mailboxes":9223372036854775807,"glouton.access":true}`
	id := string(bytes.Repeat([]byte{0xff}, 64))
	var body bytes.Buffer
	body.WriteString(`{"version":1,"entitlements_revision":1,"spaces":[`)
	for i := 0; body.Len() < directory.MaxSnapshotBytes-512; i++ {
		fmt.Fprintf(&body, `{"id":"%s%08d","entitlements":%s},`, id, i, values)
	}
	body.WriteString(`{"id":"last"}]}`)
	var snap directory.Snapshot
	if err := json.Unmarshal(body.Bytes(), &snap); err != nil || body.Len() > directory.MaxSnapshotBytes {
		t.Fatalf("the %d-byte snapshot is unusable: %v", body.Len(), err)
	}
	store := NewStore(features()...)
	store.Apply(snap)
	document, err := store.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	restored := NewStore(features()...)
	if err := restored.Import(document); err != nil {
		t.Fatalf("Import of a %d-byte export: %v", len(document), err)
	}
	if got := restored.Limit(Scope{SpaceID: snap.Spaces[0].ID}, "courrier.mailboxes"); got != 9223372036854775807 {
		t.Errorf("the restored first space reads %d", got)
	}
}
