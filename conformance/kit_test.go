package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/oidc"
	"github.com/FacileStudio/porte/session"

	"github.com/go-chi/chi/v5"
)

const (
	userSubject = "subject-1"
	userID      = 7
)

type users struct{}

func (users) UpsertFromOIDC(context.Context, porte.Claims) (int64, error) { return userID, nil }

type codes struct{}

func (codes) Create(context.Context, porte.LoginCode) error { return nil }

func (codes) Consume(context.Context, string) (porte.LoginCode, error) {
	return porte.LoginCode{}, porte.ErrNotFound
}

func (codes) DeleteExpired(context.Context, time.Time) (int64, error) { return 0, nil }

type app struct {
	router   http.Handler
	sessions *sessions
}

func configFrom(env map[string]string) porte.Config {
	return porte.Config{
		Issuer:          env["OIDC_ISSUER"],
		ClientID:        env["OIDC_CLIENT_ID"],
		ClientSecret:    env["OIDC_CLIENT_SECRET"],
		RedirectURL:     env["OIDC_REDIRECT_URL"],
		SuccessURL:      env["OIDC_SUCCESS_URL"],
		SSOOnly:         env["SSO_ONLY"] == "true",
		MachineAudience: env["OIDC_MACHINE_AUDIENCE"],
		ScopePrefix:     env["OIDC_SCOPE_PREFIX"],
		CLIAudience:     env["OIDC_CLI_AUDIENCE"],
	}
}

func oidcEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"OIDC_ISSUER":        issuer,
		"OIDC_CLIENT_ID":     clientID,
		"OIDC_CLIENT_SECRET": "conformance-secret",
		"OIDC_REDIRECT_URL":  "https://app.test/api/auth/oidc/callback",
		"OIDC_SUCCESS_URL":   "https://app.test/",
	}
	for key, value := range extra {
		env[key] = value
	}
	return env
}

func newApp(t *testing.T, env map[string]string, extra func() map[string]any) app {
	t.Helper()
	cfg := configFrom(env)
	store := newSessions()
	manager, err := session.New(cfg, session.Deps{Sessions: store})
	if err != nil {
		t.Fatalf("building the session manager: %v", err)
	}
	known := identities{issuer + "|" + userSubject: {UserID: userID, Provider: issuer, Subject: userSubject}}
	kit, err := oidc.New(context.Background(), cfg, oidc.Deps{
		Users: users{}, Identities: known, Codes: codes{}, Sessions: manager, ConfigExtra: extra,
	})
	if err != nil {
		t.Fatalf("building the kit: %v", err)
	}
	router := chi.NewRouter()
	manager.Mount(router)
	kit.Mount(router)
	router.With(kit.RequireAuth).HandleFunc("/probe", ok)
	return app{router: router, sessions: store}
}

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func (a app) serve(r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	a.router.ServeHTTP(recorder, r)
	return recorder
}

func (a app) issue(t *testing.T, user int64) string {
	t.Helper()
	token, err := porte.NewToken()
	if err != nil {
		t.Fatalf("minting a token: %v", err)
	}
	_, err = a.sessions.Create(context.Background(), porte.Session{
		TokenHash: porte.HashToken(token), UserID: user, LastUsedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("storing a session: %v", err)
	}
	return token
}

func body(recorder *httptest.ResponseRecorder) string {
	return recorder.Body.String()
}
