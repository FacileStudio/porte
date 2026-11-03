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
