package session

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

func scopedManager(t *testing.T, prefix string, identity porte.Identity) *Manager {
	t.Helper()
	manager, err := New(porte.Config{SuccessURL: "https://app.test/", ScopePrefix: prefix}, Deps{
		Sessions: newMemory(),
		Logger:   slog.New(slog.DiscardHandler),
		Now:      time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manager.WithJWT(&stubJWT{accepted: map[string]porte.Identity{"aaa.bbb.ccc": identity}})
	return manager
}

func scopedStatus(manager *Manager, method string) int {
	request := httptest.NewRequest(method, "/x", nil)
	request.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, request)
	return recorder.Code
}

func TestTheScopeGateFollowsTheMethodAndTheClaim(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		scopes []string
		method string
		want   int
	}{
		{"read scope reads", "courrier", []string{"courrier.read"}, http.MethodGet, http.StatusOK},
		{"read scope heads", "courrier", []string{"courrier.read"}, http.MethodHead, http.StatusOK},
		{"read scope cannot write", "courrier", []string{"courrier.read"}, http.MethodPost, http.StatusForbidden},
		{"read scope cannot delete", "courrier", []string{"courrier.read"}, http.MethodDelete, http.StatusForbidden},
		{"write scope writes", "courrier", []string{"courrier.write"}, http.MethodPost, http.StatusOK},
		{"write scope reads", "courrier", []string{"courrier.write"}, http.MethodGet, http.StatusOK},
		{"another app's scope is refused", "courrier", []string{"agenda.read"}, http.MethodGet, http.StatusForbidden},
		{"no scope claim is refused", "courrier", nil, http.MethodGet, http.StatusForbidden},
		{"no prefix leaves a scopeless token alone", "", nil, http.MethodPost, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			manager := scopedManager(t, c.prefix, porte.Identity{Subject: "u", Scopes: c.scopes})
			if got := scopedStatus(manager, c.method); got != c.want {
				t.Fatalf("%s with scopes %v = %d, want %d", c.method, c.scopes, got, c.want)
			}
		})
	}
}

func TestTheScopeGateNeverTouchesACookieSession(t *testing.T) {
	now := time.Now()
	store := newMemory()
	manager, err := New(porte.Config{SuccessURL: "https://app.test/", ScopePrefix: "courrier"}, Deps{
		Sessions: store,
		Logger:   slog.New(slog.DiscardHandler),
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, _, err := manager.Issue(t.Context(), 7, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	recorder := httptest.NewRecorder()
	authenticated(manager).ServeHTTP(recorder, cookieRequest(manager, token))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a cookie session answered %d, want 200 — the gate is for bearer JWTs", recorder.Code)
	}
}

func TestEveryScopeRefusalIsTheSameBody(t *testing.T) {
	missing := scopedManager(t, "courrier", porte.Identity{Subject: "u"})
	wrongApp := scopedManager(t, "courrier", porte.Identity{Subject: "u", Scopes: []string{"agenda.read"}})
	bodies := map[string]bool{}
	for _, manager := range []*Manager{missing, wrongApp} {
		request := httptest.NewRequest(http.MethodGet, "/x", nil)
		request.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
		recorder := httptest.NewRecorder()
		authenticated(manager).ServeHTTP(recorder, request)
		bodies[recorder.Body.String()] = true
	}
	if len(bodies) != 1 {
		t.Fatalf("refusals differ: %v", bodies)
	}
}
