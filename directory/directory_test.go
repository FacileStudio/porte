package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSyncAppliesOnlyANewVersion pins the two properties apps rely on: the
// pull authenticates with the client's own credentials, and a snapshot whose
// version was already applied is not applied twice.
func TestSyncAppliesOnlyANewVersion(t *testing.T) {
	version := int64(1)
	registre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "app" || secret != "s3cret" || r.URL.Path != "/api/directory/snapshot" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(Snapshot{Version: version, Spaces: []Space{{ID: "x", Name: "Facile"}}})
	}))
	defer registre.Close()

	var applied atomic.Int32
	syncer := &Syncer{
		Client: Client{Issuer: registre.URL, ClientID: "app", ClientSecret: "s3cret"},
		Apply: func(_ context.Context, s Snapshot) error {
			applied.Add(1)
			return nil
		},
	}
	for range 2 {
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("Sync: %v", err)
		}
	}
	version = 2
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if applied.Load() != 2 {
		t.Errorf("applied %d times, want 2: once for version 1, once for version 2", applied.Load())
	}
}

// TestTheNudgeHandlerAcceptsOnlyPost keeps the route from answering anything
// but the nudge it exists for.
func TestTheNudgeHandlerAcceptsOnlyPost(t *testing.T) {
	handler := (&Syncer{}).Handler()
	for method, want := range map[string]int{http.MethodPost: http.StatusAccepted, http.MethodGet: http.StatusMethodNotAllowed} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, SyncPath, nil))
		if recorder.Code != want {
			t.Errorf("%s answered %d, want %d", method, recorder.Code, want)
		}
	}
}

// TestTheSnapshotCarriesEntitlements pins the additive wire shape: a snapshot
// from an older Registre still decodes, and the new fields round-trip raw.
func TestTheSnapshotCarriesEntitlements(t *testing.T) {
	var old Snapshot
	if err := json.Unmarshal([]byte(`{"version":3,"spaces":[{"id":"a","name":"A","members":[]}]}`), &old); err != nil {
		t.Fatalf("decode an old snapshot: %v", err)
	}
	if old.People != nil || old.Spaces[0].Entitlements != nil {
		t.Errorf("an old snapshot decoded entitlements: %+v", old)
	}
	body := `{"version":4,"entitlements_revision":9,"spaces":[{"id":"a","name":"A","members":[],"entitlements":{"glouton.access":true}}],` +
		`"people":[{"sub":"u1","entitlements":{"nuage.storage_gb":500}}]}`
	var snapshot Snapshot
	if err := json.Unmarshal([]byte(body), &snapshot); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(snapshot.Spaces[0].Entitlements["glouton.access"]); got != "true" {
		t.Errorf("space entitlement = %q, want true", got)
	}
	if snapshot.EntitlementsRevision != 9 {
		t.Errorf("entitlements revision = %d, want 9", snapshot.EntitlementsRevision)
	}
	if len(snapshot.People) != 1 || snapshot.People[0].Subject != "u1" ||
		string(snapshot.People[0].Entitlements["nuage.storage_gb"]) != "500" {
		t.Errorf("people = %+v", snapshot.People)
	}
	encoded, err := json.Marshal(Snapshot{Version: 1, Spaces: []Space{{ID: "a"}}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if want := `{"version":1,"spaces":[{"id":"a","name":"","members":null}]}`; string(encoded) != want {
		t.Errorf("encoded %s, want %s", encoded, want)
	}
}

// TestConcurrentSyncsAreRaceFree is for the race detector: a boot Sync and
// Run's own pulls may overlap.
func TestConcurrentSyncsAreRaceFree(t *testing.T) {
	registre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Snapshot{Version: 1})
	}))
	defer registre.Close()
	syncer := &Syncer{
		Client: Client{Issuer: registre.URL},
		Apply:  func(context.Context, Snapshot) error { return nil },
	}
	done := make(chan error, 4)
	for range 4 {
		go func() { done <- syncer.Sync(context.Background()) }()
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Errorf("Sync: %v", err)
		}
	}
}
