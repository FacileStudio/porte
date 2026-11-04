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
