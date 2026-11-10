package exchange_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

const (
	issuerPath = ""
	clientID   = "nuage-client"
	secret     = "s3cret"
)

type fakeRegistre struct {
	server *httptest.Server

	mu          sync.Mutex
	refresh     map[string]bool
	access      map[string]bool
	grants      map[string][]string
	serial      int
	expiresIn   int
	refreshes   atomic.Int32
	exchanges   atomic.Int32
	inFlight    atomic.Int32
	overlapping atomic.Bool
	down        atomic.Bool
}

func newFakeRegistre(t *testing.T) *fakeRegistre {
	t.Helper()
	f := &fakeRegistre{
		refresh:   map[string]bool{},
		access:    map[string]bool{},
		grants:    map[string][]string{"bulle": {"bulle.read", "bulle.write"}, "courrier": {"courrier.read"}},
		expiresIn: 300,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": f.server.URL + "/oauth/token"})
	})
	mux.HandleFunc("POST /oauth/token", f.token)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeRegistre) issuer() string { return f.server.URL + issuerPath }

func (f *fakeRegistre) mint(prefix string, set map[string]bool) string {
	f.serial++
	value := fmt.Sprintf("%s-%d", prefix, f.serial)
	set[value] = true
	return value
}

func (f *fakeRegistre) seed() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mint("rt", f.refresh)
}

func (f *fakeRegistre) revokeAccess() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access = map[string]bool{}
}

func reply(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeRegistre) token(w http.ResponseWriter, r *http.Request) {
	if f.down.Load() {
		reply(w, http.StatusBadGateway, map[string]any{})
		return
	}
	if id, pw, ok := r.BasicAuth(); !ok || id != clientID || pw != secret {
		reply(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	_ = r.ParseForm()
	switch r.PostForm.Get("grant_type") {
	case "refresh_token":
		f.rotate(w, r.PostForm.Get("refresh_token"))
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		f.exchange(w, r)
	default:
		reply(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
	}
}

func (f *fakeRegistre) rotate(w http.ResponseWriter, used string) {
	f.refreshes.Add(1)
	if f.inFlight.Add(1) > 1 {
		f.overlapping.Store(true)
	}
	defer f.inFlight.Add(-1)
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.refresh[used] {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	delete(f.refresh, used)
	reply(w, http.StatusOK, map[string]any{
		"access_token": f.mint("at", f.access), "refresh_token": f.mint("rt", f.refresh), "expires_in": 900,
	})
}

func (f *fakeRegistre) exchange(w http.ResponseWriter, r *http.Request) {
	f.exchanges.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.access[r.PostForm.Get("subject_token")] {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	audience := r.PostForm.Get("audience")
	granted, ok := f.grants[audience]
	if !ok {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_target"})
		return
	}
	for _, scope := range strings.Fields(r.PostForm.Get("scope")) {
		if !contains(granted, scope) {
			reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
			return
		}
	}
	f.serial++
	reply(w, http.StatusOK, map[string]any{
		"access_token": fmt.Sprintf("x-%s-%d", audience, f.serial), "expires_in": f.expiresIn,
	})
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

type memoryIdentities struct {
	mu      sync.Mutex
	rows    map[int64]porte.StoredIdentity
	saves   atomic.Int32
	failing atomic.Bool
	stale   string
}

func (m *memoryIdentities) ListByUser(_ context.Context, userID int64) ([]porte.StoredIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[userID]
	if !ok {
		return nil, nil
	}
	if m.stale != "" {
		row.Tokens.RefreshToken, m.stale = m.stale, ""
	}
	local := porte.StoredIdentity{UserID: userID, Provider: porte.ProviderLocal, Subject: "1", PasswordHash: "x"}
	leftover := porte.StoredIdentity{UserID: userID, Provider: row.Provider, Subject: "old-subject"}
	return []porte.StoredIdentity{local, leftover, row}, nil
}

func (m *memoryIdentities) Save(_ context.Context, identity porte.StoredIdentity) error {
	if m.failing.Load() {
		return fmt.Errorf("database down")
	}
	m.saves.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[identity.UserID] = identity
	return nil
}

func (m *memoryIdentities) refreshToken(userID int64) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[userID].Tokens.RefreshToken
}

func (m *memoryIdentities) setRefreshToken(userID int64, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := m.rows[userID]
	row.Tokens.RefreshToken = token
	m.rows[userID] = row
}
