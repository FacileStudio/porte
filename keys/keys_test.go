package keys

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/go-chi/chi/v5"
)

type memStore struct {
	keys  map[int64]Key
	usage map[int64]int64
	seq   int64
}

func newMemStore() *memStore {
	return &memStore{
		keys:  make(map[int64]Key),
		usage: make(map[int64]int64),
	}
}

func (s *memStore) Create(ctx context.Context, key Key) (Key, error) {
	s.seq++
	key.ID = s.seq
	s.keys[key.ID] = key
	return key, nil
}

func (s *memStore) FindByHash(ctx context.Context, tokenHash string) (Key, error) {
	for _, k := range s.keys {
		if k.TokenHash == tokenHash {
			return k, nil
		}
	}
	return Key{}, porte.ErrNotFound
}

func (s *memStore) List(ctx context.Context, app string) ([]Key, error) {
	var list []Key
	for _, k := range s.keys {
		if app == "" || k.App == app {
			list = append(list, k)
		}
	}
	return list, nil
}

func (s *memStore) Revoke(ctx context.Context, id int64) error {
	k, ok := s.keys[id]
	if !ok {
		return porte.ErrNotFound
	}
	now := time.Now().UTC()
	k.RevokedAt = &now
	s.keys[id] = k
	return nil
}

func (s *memStore) RecordUsage(ctx context.Context, keyID int64, count int64) error {
	s.usage[keyID] += count
	return nil
}

func (s *memStore) UsageToday(ctx context.Context) (map[int64]int64, error) {
	out := make(map[int64]int64)
	for k, v := range s.usage {
		out[k] = v
	}
	return out, nil
}

func TestGenerateToken(t *testing.T) {
	raw, prefix, hash, err := GenerateToken("journal", "testapp", KindSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raw) == 0 || len(prefix) == 0 || len(hash) == 0 {
		t.Fatalf("empty token output")
	}
	if hash != porte.HashToken(raw) {
		t.Fatalf("hash mismatch")
	}
}

func TestManagerEndpoints(t *testing.T) {
	store := newMemStore()
	mgr := NewManager(store, "testsvc")

	r := chi.NewRouter()
	mgr.Mount(r)

	createBody, _ := json.Marshal(CreateRequest{
		App:        "testapp",
		Kind:       KindSecret,
		DailyQuota: 100,
	})
	req := httptest.NewRequest(http.MethodPost, "/apikeys", bytes.NewReader(createBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var createResp CreateResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createResp)
	if createResp.Key.App != "testapp" || createResp.Token == "" {
		t.Fatalf("unexpected create response: %+v", createResp)
	}

	req = httptest.NewRequest(http.MethodGet, "/apikeys?app=testapp", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/apikeys/1", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d", rec.Code)
	}
}

func TestManagerAuthentication(t *testing.T) {
	store := newMemStore()
	mgr := NewManager(store, "testsvc")

	rawToken, prefix, tokenHash, _ := GenerateToken("testsvc", "clientapp", KindPublic)
	_, _ = store.Create(context.Background(), Key{
		App:            "clientapp",
		Kind:           KindPublic,
		Prefix:         prefix,
		TokenHash:      tokenHash,
		AllowedOrigins: []string{"https://example.com"},
		DailyQuota:     2,
	})

	protected := mgr.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k, ok := From(r.Context())
		if !ok || k.App != "clientapp" {
			http.Error(w, "missing context key", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing key, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/test?key="+rawToken, nil)
	req.Header.Set("Origin", "https://unauthorized.com")
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong origin, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Origin", "https://example.com")
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid key, got %d", rec.Code)
	}
}
