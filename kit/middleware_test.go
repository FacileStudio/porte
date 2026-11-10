package kit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/kit"
	"github.com/FacileStudio/tronc/errors"
)

type stubAuth struct {
	userID int64
}

func (a stubAuth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.userID != 0 {
			r = r.WithContext(porte.WithIdentity(r.Context(), porte.Identity{UserID: a.userID}))
		}
		next.ServeHTTP(w, r)
	})
}

type stubResolver map[int64]kit.Identity

func (s stubResolver) Identity(_ context.Context, userID int64) (kit.Identity, error) {
	identity, ok := s[userID]
	if !ok {
		return kit.Identity{}, errors.Unauthorized("invalid auth token")
	}
	return identity, nil
}

func serveThrough(auth stubAuth, users stubResolver) (*httptest.ResponseRecorder, *kit.Identity) {
	var seen *kit.Identity
	handler := kit.RequireAuth(auth, users)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity, ok := kit.FromContext(r.Context()); ok {
			seen = &identity
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/probe", nil))
	return recorder, seen
}

func TestRequireAuthHydratesTheIdentity(t *testing.T) {
	want := kit.Identity{UserID: 7, Email: "camille@facile.studio", Name: "Camille", IsAdmin: true}
	recorder, seen := serveThrough(stubAuth{userID: 7}, stubResolver{7: want})
	if recorder.Code != http.StatusNoContent || seen == nil || *seen != want {
		t.Fatalf("status %d, identity %+v, want %+v", recorder.Code, seen, want)
	}
}

func TestRequireAuthRefusesASessionWhoseUserIsGone(t *testing.T) {
	recorder, seen := serveThrough(stubAuth{userID: 7}, stubResolver{})
	if recorder.Code != http.StatusUnauthorized || seen != nil {
		t.Fatalf("status %d, identity %+v", recorder.Code, seen)
	}
}

func TestRequireAuthRefusesWithoutAPorteIdentity(t *testing.T) {
	recorder, seen := serveThrough(stubAuth{}, stubResolver{})
	if recorder.Code != http.StatusUnauthorized || seen != nil {
		t.Fatalf("status %d, identity %+v", recorder.Code, seen)
	}
}

func TestFromContextReportsAbsence(t *testing.T) {
	if _, ok := kit.FromContext(context.Background()); ok {
		t.Fatal("an empty context carried an identity")
	}
	ctx := kit.WithIdentity(context.Background(), kit.Identity{UserID: 3})
	if identity, ok := kit.FromContext(ctx); !ok || identity.UserID != 3 {
		t.Fatalf("identity = %+v, %v", identity, ok)
	}
}
