package session

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/tronc/errors"
)

// goneIdentity is a store whose bound inserts find their identity purged.
type goneIdentity struct{ *memory }

func (g goneIdentity) Create(ctx context.Context, session porte.Session) (porte.Session, error) {
	if session.Provider != "" {
		return porte.Session{}, porte.ErrNotFound
	}
	return g.memory.Create(ctx, session)
}

// TestABoundSessionWhoseIdentityIsGoneIsAGeneric401 pins the manager's half:
// the store's ErrNotFound becomes an ordinary refusal, and no cookie is set.
func TestABoundSessionWhoseIdentityIsGoneIsAGeneric401(t *testing.T) {
	manager, err := New(porte.Config{SuccessURL: "https://app.test/"}, Deps{
		Sessions: goneIdentity{newMemory()},
		Now:      time.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://app.test/cb", nil)
	_, _, err = manager.IssueCookieFor(context.Background(), recorder, request,
		porte.Session{UserID: 1, Provider: "https://sso.test", Subject: "gone"})
	var refusal *errors.Error
	if !stderrors.As(err, &refusal) || refusal.Code != errors.Unauthorized("").Code {
		t.Fatalf("IssueCookieFor = %v, want a 401", err)
	}
	if len(recorder.Result().Cookies()) != 0 {
		t.Error("a refused bound session set a cookie")
	}
	if _, _, err := manager.Issue(context.Background(), 1, ""); err != nil {
		t.Errorf("an unbound session was refused: %v", err)
	}
}

// recording is a store that keeps the last template it was asked to store.
type recording struct {
	*memory
	last porte.Session
}

func (r *recording) Create(ctx context.Context, session porte.Session) (porte.Session, error) {
	r.last = session
	return r.memory.Create(ctx, session)
}

// TestANamedTokenIsBoundToItsCaller pins both caller shapes: a cookie session
// binds by IssuedBy, a bearer JWT by its issuer identity, and a token for
// someone else, or with no caller, stays as asked.
func TestANamedTokenIsBoundToItsCaller(t *testing.T) {
	store := &recording{memory: newMemory()}
	manager, err := New(porte.Config{Issuer: "https://registre.test"}, Deps{Sessions: store, Now: time.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name   string
		caller *porte.Identity
		want   porte.Session
	}{
		{"cookie session", &porte.Identity{UserID: 1, SessionID: 9}, porte.Session{IssuedBy: 9}},
		{"bearer JWT", &porte.Identity{UserID: 1, Subject: "sub-1"}, porte.Session{Provider: "https://registre.test", Subject: "sub-1"}},
		{"another user", &porte.Identity{UserID: 2, SessionID: 9}, porte.Session{}},
		{"no caller", nil, porte.Session{}},
	}
	for _, c := range cases {
		ctx := context.Background()
		if c.caller != nil {
			ctx = porte.WithIdentity(ctx, *c.caller)
		}
		if _, _, err := manager.Issue(ctx, 1, "ci"); err != nil {
			t.Fatalf("%s: Issue: %v", c.name, err)
		}
		got := store.last
		if got.IssuedBy != c.want.IssuedBy || got.Provider != c.want.Provider || got.Subject != c.want.Subject {
			t.Errorf("%s: bound to %+v, want %+v", c.name, got, c.want)
		}
	}
}
