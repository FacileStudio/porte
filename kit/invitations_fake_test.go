package kit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/porte/kit"
)

type registreFake struct {
	server *httptest.Server
	calls  atomic.Int64
	mu     sync.Mutex
	status int
	body   string
	delay  time.Duration
	auth   string
}

func newRegistreFake(t *testing.T, count int) *registreFake {
	t.Helper()
	fake := &registreFake{status: http.StatusOK}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	fake.answer(count)
	return fake
}

func (f *registreFake) answer(count int) {
	invitations := make([]map[string]any, 0, count)
	for i := range count {
		id := string(rune('a' + i))
		invitations = append(invitations, map[string]any{"id": id, "space_name": "S", "role": "member",
			"invited_by": "Noah", "expires_at": "2026-11-24T10:00:00Z", "url": f.server.URL + "/invitations/" + id})
	}
	body, _ := json.Marshal(map[string]any{"count": count, "invitations": invitations})
	f.set(http.StatusOK, string(body))
}

func (f *registreFake) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *registreFake) serve(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	f.mu.Lock()
	status, body, delay := f.status, f.body, f.delay
	f.auth = r.Header.Get("Authorization")
	f.mu.Unlock()
	if id, secret, _ := r.BasicAuth(); id != "nuage" || secret != "s3cret" ||
		r.URL.Path != directory.InvitationsPath || !strings.HasPrefix(r.URL.Query().Get("sub"), "sub-") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	select {
	case <-time.After(delay):
	case <-r.Context().Done():
		return
	}
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "2")
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

type identities struct {
	byUser map[int64][]porte.StoredIdentity
	err    error
	calls  atomic.Int64
}

func (s *identities) ListByUser(_ context.Context, userID int64) ([]porte.StoredIdentity, error) {
	s.calls.Add(1)
	return s.byUser[userID], s.err
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type harness struct {
	fake    *registreFake
	users   *identities
	clock   *clock
	logs    *safeWriter
	handler http.Handler
}

func newHarness(t *testing.T, count, maxEntries int) *harness {
	t.Helper()
	fake := newRegistreFake(t, count)
	h := &harness{fake: fake, clock: &clock{now: time.Unix(1_800_000_000, 0)}, logs: &safeWriter{}}
	h.users = &identities{byUser: map[int64][]porte.StoredIdentity{}}
	for id := int64(1); id <= 5; id++ {
		h.users.byUser[id] = []porte.StoredIdentity{
			{UserID: id, Provider: "https://other.test", Subject: "wrong"},
			{UserID: id, Provider: fake.server.URL + "/", Subject: "sub-" + string(rune('0'+id))},
		}
	}
	handler, err := kit.NewInvitations(kit.InvitationsConfig{
		Directory: directory.Client{Issuer: fake.server.URL, ClientID: "nuage", ClientSecret: "s3cret",
			HTTP: fake.server.Client()},
		Identities: h.users,
		Logger:     slog.New(slog.NewTextHandler(h.logs, nil)),
		MaxEntries: maxEntries,
		Now:        h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.handler = handler
	return h
}

func (h *harness) ask(t *testing.T, userID int64) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, kit.InvitationsPath, nil)
	if userID != 0 {
		request = request.WithContext(porte.WithIdentity(request.Context(), porte.Identity{UserID: userID}))
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("invitations answered %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("invitations body %q: %v", recorder.Body, err)
	}
	return body
}

func (h *harness) warned() bool {
	h.logs.mu.Lock()
	defer h.logs.mu.Unlock()
	return strings.Contains(h.logs.buf.String(), "level=WARN")
}

var errStore = errors.New("store down")

type safeWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *safeWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
