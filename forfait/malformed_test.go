package forfait

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/FacileStudio/porte/directory"
)

// TestMalformedValuesFallBackToTheDefault feeds every shape that is not a
// JSON bool or an integer of at least -1.
func TestMalformedValuesFallBackToTheDefault(t *testing.T) {
	limits := []string{`null`, `"100"`, `1.5`, `1e3`, `-2`, `true`, `{}`, `[]`, `99999999999999999999`, ``, `  `, `{`}
	for _, literal := range limits {
		store := applied(map[string]string{"nuage.storage_gb": literal}, nil)
		if got := store.Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 5 {
			t.Errorf("limit %q: Limit = %d, want the default 5", literal, got)
		}
	}
	bools := []string{`null`, `"true"`, `1`, `0`, `True`, `{}`, ``}
	for _, literal := range bools {
		store := applied(map[string]string{"glouton.access": literal}, nil)
		if store.Enabled(Scope{SpaceID: "pro"}, "glouton.access") {
			t.Errorf("bool %q enabled glouton.access", literal)
		}
	}
	if got := applied(map[string]string{"nuage.storage_gb": ` 42 `}, nil).Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 42 {
		t.Errorf("a padded integer read %d, want 42", got)
	}
}

// TestBadDeclarationsNeverPanic pins that NewStore skips malformed keys,
// keeps the first of a duplicate and turns a malformed default into a denial.
func TestBadDeclarationsNeverPanic(t *testing.T) {
	store := NewStore(
		Feature{Key: "Nuage.Storage", Kind: Limit, Default: json.RawMessage(`9`)},
		Feature{Key: "a.b", Kind: Limit, Default: json.RawMessage(`3`)},
		Feature{Key: "a.b", Kind: Limit, Default: json.RawMessage(`7`)},
		Feature{Key: "c.d", Kind: Limit},
		Feature{Key: "e.f", Kind: Bool, Default: json.RawMessage(`"yes"`)},
		Feature{Key: "g.h", Kind: Kind(42), Default: json.RawMessage(`true`)},
	)
	store.Apply(directory.Snapshot{EntitlementsRevision: 1, People: []directory.Person{{Subject: "u"}}})
	sc := Scope{Subject: "u"}
	if store.Limit(sc, "Nuage.Storage") != 0 || store.Limit(sc, "a.b") != 3 || store.Limit(sc, "c.d") != 0 {
		t.Error("a bad limit declaration did not resolve to a denial or the first declaration")
	}
	if store.Enabled(sc, "e.f") || store.Enabled(sc, "g.h") {
		t.Error("a bad bool declaration enabled a feature")
	}
}

// TestAnOversizedScopeReadsAsDefaults pins the 200-key ceiling per scope.
func TestAnOversizedScopeReadsAsDefaults(t *testing.T) {
	values := map[string]string{"nuage.storage_gb": "500"}
	for i := range maxKeys {
		values[fmt.Sprintf("pad.k%d", i)] = "1"
	}
	if got := applied(values, nil).Limit(Scope{SpaceID: "pro"}, "nuage.storage_gb"); got != 5 {
		t.Errorf("a scope with %d keys read %d, want the default 5", len(values), got)
	}
}
