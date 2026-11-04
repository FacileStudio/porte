package local

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

// federatedKit is a kit whose session manager has an OIDC issuer, with
// registration open, which is exactly the setting the issuer overrides.
func federatedKit(t *testing.T, issuer string) *Kit {
	t.Helper()
	store := newStores()
	manager, err := session.New(porte.Config{Issuer: issuer}, session.Deps{Sessions: sessionStore{store}})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	kit, err := New(Config{AllowRegistration: true}, Deps{
		Users: store, Identities: store, Sessions: manager, Count: store.count,
	})
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return kit
}

// post sends one credentials body to a router with the kit mounted.
func post(kit *Kit, path string) int {
	router := chi.NewRouter()
	kit.Mount(router)
	recorder := httptest.NewRecorder()
	body := strings.NewReader(`{"email":"someone@facile.studio","name":"S","password":"a-long-enough-password"}`)
	request := httptest.NewRequest(http.MethodPost, path, body)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder.Code
}

// TestAnOIDCConfiguredKitServesNoPasswordRoute pins the launch rule: with an
// issuer, /auth/register and /auth/login are not there, even with
// AllowRegistration, while the same kit without an issuer still serves them.
func TestAnOIDCConfiguredKitServesNoPasswordRoute(t *testing.T) {
	federated := federatedKit(t, "https://registre.facile.studio")
	for _, path := range []string{porte.RouteRegister, porte.RouteLoginLocal} {
		if code := post(federated, path); code != http.StatusNotFound {
			t.Errorf("POST %s with OIDC configured answered %d, want 404", path, code)
		}
	}
	plain := federatedKit(t, "")
	if code := post(plain, porte.RouteRegister); code != http.StatusCreated {
		t.Errorf("POST %s without OIDC answered %d, want 201", porte.RouteRegister, code)
	}
	if code := post(plain, porte.RouteLoginLocal); code != http.StatusOK {
		t.Errorf("POST %s without OIDC answered %d, want 200", porte.RouteLoginLocal, code)
	}
}

// TestAnOIDCConfiguredKitRefusesProgrammaticCalls pins that an app's own
// handler calling Register or Login cannot reopen the password path.
func TestAnOIDCConfiguredKitRefusesProgrammaticCalls(t *testing.T) {
	kit := federatedKit(t, "https://registre.facile.studio")
	w, r := request()
	if _, _, err := kit.Register(context.Background(), w, r, "a@facile.studio", "A", "a-long-enough-password"); !stderrors.Is(err, porte.ErrPasswordLoginDisabled) {
		t.Errorf("Register = %v, want ErrPasswordLoginDisabled", err)
	}
	if _, _, err := kit.Login(context.Background(), w, r, "a@facile.studio", "a-long-enough-password"); !stderrors.Is(err, porte.ErrPasswordLoginDisabled) {
		t.Errorf("Login = %v, want ErrPasswordLoginDisabled", err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("a refused call set a session cookie")
	}
}
