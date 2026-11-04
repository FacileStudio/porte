package magiclink

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"

	"github.com/go-chi/chi/v5"
)

// federatedRig is a rig whose kit's session manager has an OIDC issuer.
func federatedRig(t *testing.T) (*rig, *Kit) {
	t.Helper()
	r := newRig(t, Config{})
	manager, err := session.New(porte.Config{Issuer: "https://registre.facile.studio"}, session.Deps{Sessions: r.sessions})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	deps := r.kit.deps
	deps.Sessions = manager
	kit, err := New(Config{}, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, kit
}

// TestAnOIDCConfiguredKitServesNoMagicLink pins the issuer gate: no route,
// and no programmatic Request or Consume, and no mail sent.
func TestAnOIDCConfiguredKitServesNoMagicLink(t *testing.T) {
	r, kit := federatedRig(t)
	router := chi.NewRouter()
	kit.Mount(router)
	for _, path := range []string{porte.RouteMagicLink, porte.RouteMagicLinkConsume} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"email":"camille@facile.studio","token":"x"}`))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("POST %s with OIDC configured answered %d, want 404", path, recorder.Code)
		}
	}
	if err := kit.Request(context.Background(), "camille@facile.studio", ""); !stderrors.Is(err, porte.ErrLocalLoginDisabled) {
		t.Errorf("Request = %v, want ErrLocalLoginDisabled", err)
	}
	kit.Wait()
	w := httptest.NewRecorder()
	if _, _, err := kit.Consume(context.Background(), w, httptest.NewRequest(http.MethodPost, "/", nil), "x"); !stderrors.Is(err, porte.ErrLocalLoginDisabled) {
		t.Errorf("Consume = %v, want ErrLocalLoginDisabled", err)
	}
	if len(r.mail.mails()) != 0 {
		t.Error("a federated kit sent a link")
	}
}
