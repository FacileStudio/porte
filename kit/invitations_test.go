package kit_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/porte/kit"
	"github.com/FacileStudio/tronc/apiref"

	"github.com/go-chi/chi/v5"
)

// TestInvitationsCountAndHref: none and several link to the issuer's spaces
// page, exactly one links to that invitation, and the app's pair is sent.
func TestInvitationsCountAndHref(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		h := newHarness(t, count, 0)
		body := h.ask(t, 1)
		want := h.fake.server.URL + "/spaces"
		if count == 1 {
			want = h.fake.server.URL + "/invitations/a"
		}
		if body["count"] != float64(count) || body["href"] != want {
			t.Errorf("%d invitations answered %v, want href %s", count, body, want)
		}
		h.fake.mu.Lock()
		auth := h.fake.auth
		h.fake.mu.Unlock()
		if auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("nuage:s3cret")) {
			t.Errorf("Registre saw Authorization %q", auth)
		}
	}
}

// TestInvitationsAreCachedPerUser: a second ask inside InvitationsTTL costs
// nothing, one after it asks again, and users do not share an answer.
func TestInvitationsAreCachedPerUser(t *testing.T) {
	h := newHarness(t, 1, 0)
	h.ask(t, 1)
	h.clock.advance(kit.InvitationsTTL - time.Second)
	h.fake.answer(2)
	if body := h.ask(t, 1); body["count"] != float64(1) || h.fake.calls.Load() != 1 {
		t.Fatalf("inside the TTL: %v after %d calls", body, h.fake.calls.Load())
	}
	h.clock.advance(time.Second)
	if body := h.ask(t, 1); body["count"] != float64(2) || h.fake.calls.Load() != 2 {
		t.Fatalf("after the TTL: %v after %d calls", body, h.fake.calls.Load())
	}
	if h.ask(t, 2); h.fake.calls.Load() != 3 {
		t.Fatalf("a second user reused the first one's answer")
	}
}

// TestConcurrentAsksShareOneCall: fifty requests for one user at once cost
// Registre one call.
func TestConcurrentAsksShareOneCall(t *testing.T) {
	h := newHarness(t, 1, 0)
	h.fake.delay = 200 * time.Millisecond
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ask(t, 1)
		}()
	}
	wg.Wait()
	if calls := h.fake.calls.Load(); calls != 1 {
		t.Fatalf("50 concurrent asks made %d calls, want 1", calls)
	}
	if calls := h.users.calls.Load(); calls != 1 {
		t.Fatalf("50 concurrent asks read the identities %d times, want 1", calls)
	}
}

// TestEveryFailureAnswersZeroAndIsCached: whatever goes wrong the page gets
// 200 {"count":0}, the failure is logged at warn, and nothing is retried
// inside InvitationsTTL.
func TestEveryFailureAnswersZeroAndIsCached(t *testing.T) {
	cases := map[string]func(*harness){
		"busy":      func(h *harness) { h.fake.set(http.StatusServiceUnavailable, `{"error":"busy"}`) },
		"500":       func(h *harness) { h.fake.set(http.StatusInternalServerError, `{"error":"internal error"}`) },
		"refused":   func(h *harness) { h.fake.set(http.StatusUnauthorized, `{"error":"unauthorized"}`) },
		"malformed": func(h *harness) { h.fake.set(http.StatusOK, `{"count":`) },
		"mismatch":  func(h *harness) { h.fake.set(http.StatusOK, `{"count":3,"invitations":[]}`) },
		"oversized": func(h *harness) {
			h.fake.set(http.StatusOK, `{"count":0,"invitations":[],"x":"`+strings.Repeat("a", directory.MaxInvitationsBytes)+`"}`)
		},
		"down": func(h *harness) { h.fake.server.Close() },
	}
	for name, breakIt := range cases {
		h := newHarness(t, 1, 0)
		breakIt(h)
		body := h.ask(t, 1)
		if body["count"] != float64(0) || body["href"] != nil || !h.warned() {
			t.Errorf("%s: answered %v, warned %v", name, body, h.warned())
		}
		calls := h.fake.calls.Load()
		h.clock.advance(kit.InvitationsTTL - time.Second)
		if h.ask(t, 1); h.fake.calls.Load() != calls {
			t.Errorf("%s: the failure was retried inside the TTL", name)
		}
	}
}

// TestAStalledRegistreCostsAtMostTheTimeout: a Registre that never answers
// holds the page for at most directory.InvitationsTimeout.
func TestAStalledRegistreCostsAtMostTheTimeout(t *testing.T) {
	h := newHarness(t, 1, 0)
	h.fake.delay = time.Minute
	started := time.Now()
	body := h.ask(t, 1)
	if elapsed := time.Since(started); body["count"] != float64(0) || elapsed > directory.InvitationsTimeout+time.Second {
		t.Fatalf("a stalled Registre answered %v after %s", body, elapsed)
	}
}

// TestNoRegistreIdentityNeverAsks: a user with no identity under the issuer,
// or only a password one, gets count 0 and Registre is not called.
func TestNoRegistreIdentityNeverAsks(t *testing.T) {
	h := newHarness(t, 1, 0)
	h.users.byUser[9] = []porte.StoredIdentity{
		{UserID: 9, Provider: "https://other.test", Subject: "x"},
		{UserID: 9, Provider: h.fake.server.URL, Subject: "sub-9", PasswordHash: "argon2"},
	}
	for _, userID := range []int64{9, 42} {
		if body := h.ask(t, userID); body["count"] != float64(0) || body["href"] != nil {
			t.Errorf("user %d answered %v", userID, body)
		}
	}
	h.users.err = errStore
	h.ask(t, 3)
	if h.fake.calls.Load() != 0 {
		t.Fatalf("Registre was called %d times for users without a subject", h.fake.calls.Load())
	}
	if body := h.ask(t, 0); body["count"] != float64(0) {
		t.Fatalf("no signed-in user answered %v", body)
	}
}

// TestTheCacheIsBoundedAndEvictsTheOldest: past MaxEntries the oldest answer
// goes first.
func TestTheCacheIsBoundedAndEvictsTheOldest(t *testing.T) {
	h := newHarness(t, 1, 2)
	for _, userID := range []int64{1, 2, 3} {
		h.ask(t, userID)
		h.clock.advance(time.Second)
	}
	h.ask(t, 3)
	h.ask(t, 2)
	if h.fake.calls.Load() != 3 {
		t.Fatalf("the two newest answers were not kept: %d calls", h.fake.calls.Load())
	}
	h.ask(t, 1)
	if h.fake.calls.Load() != 4 {
		t.Fatalf("the oldest answer outlived the bound: %d calls", h.fake.calls.Load())
	}
}

// TestMountInvitationsIsDocumented: the mounted route is GET InvitationsPath,
// InvitationsRoute documents it, and a config without credentials is refused.
func TestMountInvitationsIsDocumented(t *testing.T) {
	h := newHarness(t, 0, 0)
	router := chi.NewRouter()
	cfg := kit.InvitationsConfig{
		Directory:  directory.Client{Issuer: h.fake.server.URL, ClientID: "nuage", ClientSecret: "s3cret"},
		Identities: h.users,
	}
	router.Route("/api", func(r chi.Router) {
		if err := kit.MountInvitations(r.With(passthrough), cfg); err != nil {
			t.Fatal(err)
		}
	})
	ref := apiref.Config{Servers: []string{"/api"},
		Registry: apiref.Registry{Modules: []apiref.Module{{Name: "me", Routes: []apiref.Route{kit.InvitationsRoute()}}}}}
	if missing := apiref.Undocumented(router, ref); len(missing) != 0 {
		t.Fatalf("undocumented: %v", missing)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/me/invitations", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST answered %d", recorder.Code)
	}
	cfg.Directory.ClientSecret = ""
	if err := kit.MountInvitations(chi.NewRouter(), cfg); err == nil {
		t.Fatal("a config without a secret mounted")
	}
}

func passthrough(next http.Handler) http.Handler { return next }
