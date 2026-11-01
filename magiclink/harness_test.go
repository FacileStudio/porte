package magiclink

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/magiclink/magiclinktest"
	"github.com/FacileStudio/porte/session"
)

var clockStart = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

type sessions struct {
	porte.SessionStore
	mu    sync.Mutex
	count int
}

func (s *sessions) Create(_ context.Context, sess porte.Session) (porte.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	sess.ID = int64(s.count)
	return sess, nil
}

func (s *sessions) issued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

type links struct {
	*magiclinktest.Memory
	mu      sync.Mutex
	created []porte.MagicLink
	counts  int
}

func (l *links) Create(ctx context.Context, link porte.MagicLink) error {
	l.mu.Lock()
	l.created = append(l.created, link)
	l.mu.Unlock()
	return l.Memory.Create(ctx, link)
}

func (l *links) CountSince(ctx context.Context, key porte.LinkKey, since time.Time) (int, error) {
	l.mu.Lock()
	l.counts++
	l.mu.Unlock()
	return l.Memory.CountSince(ctx, key, since)
}

type mailbox struct {
	mu   sync.Mutex
	sent []sentMail
	fail error
	gate chan struct{}
}

type sentMail struct{ to, link string }

func (m *mailbox) send(_ context.Context, to, link string) error {
	if m.gate != nil {
		<-m.gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.sent = append(m.sent, sentMail{to: to, link: link})
	return nil
}

func (m *mailbox) mails() []sentMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentMail(nil), m.sent...)
}

func (m *mailbox) token(t *testing.T) string {
	t.Helper()
	mails := m.mails()
	if len(mails) == 0 {
		t.Fatal("no mail was sent")
	}
	parsed, err := url.Parse(mails[len(mails)-1].link)
	if err != nil || parsed.Query().Get("token") == "" {
		t.Fatalf("the mailed link carries no token: %q", mails[len(mails)-1].link)
	}
	return parsed.Query().Get("token")
}

type rig struct {
	kit      *Kit
	links    *links
	mail     *mailbox
	sessions *sessions
	logs     *bytes.Buffer
	now      time.Time
	users    map[string]int64
	refused  map[int64]bool
}

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	r := &rig{
		links:    &links{Memory: magiclinktest.NewMemory()},
		mail:     &mailbox{},
		sessions: &sessions{},
		logs:     &bytes.Buffer{},
		now:      clockStart,
		users:    map[string]int64{"camille@facile.studio": 1, "dana@facile.studio": 2, "eli@facile.studio": 3},
		refused:  map[int64]bool{},
	}
	manager, err := session.New(porte.Config{}, session.Deps{Sessions: r.sessions})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	kit, err := New(cfg, Deps{
		Links:     r.links,
		Sessions:  manager,
		Logger:    slog.New(slog.NewTextHandler(r.logs, nil)),
		FindUser:  r.findUser,
		Send:      r.mail.send,
		BuildLink: func(token string) string { return "https://app.test/login/verify?token=" + token },
		Allow:     r.allow,
		Now:       func() time.Time { return r.now },
	})
	if err != nil {
		t.Fatalf("magiclink.New: %v", err)
	}
	r.kit = kit
	return r
}

func (r *rig) findUser(_ context.Context, email string) (int64, error) {
	if id, ok := r.users[email]; ok {
		return id, nil
	}
	return 0, porte.ErrNotFound
}

func (r *rig) allow(_ context.Context, id int64) (bool, error) { return !r.refused[id], nil }

func (r *rig) request(t *testing.T, email, ip string) {
	t.Helper()
	if err := r.kit.Request(context.Background(), email, ip); err != nil {
		t.Fatalf("request %s: %v", email, err)
	}
	r.kit.Wait()
}

func (r *rig) consume(token string) (int64, *httptest.ResponseRecorder, error) {
	w := httptest.NewRecorder()
	id, _, err := r.kit.Consume(context.Background(), w, httptest.NewRequest(http.MethodPost, porte.RouteMagicLinkConsume, nil), token)
	return id, w, err
}
