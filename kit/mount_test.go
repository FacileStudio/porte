package kit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/kit"
	"github.com/FacileStudio/porte/oidc"
	"github.com/FacileStudio/porte/session"

	"github.com/go-chi/chi/v5"
)

const fakeIssuer = "https://sso.test"

type fakeIssuerTransport struct{}

func (fakeIssuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != fakeIssuer {
		return nil, errors.New("kit test: no network outside the fake issuer")
	}
	recorder := httptest.NewRecorder()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		recorder.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(recorder).Encode(map[string]any{
			"issuer": fakeIssuer, "authorization_endpoint": fakeIssuer + "/authorize",
			"token_endpoint": fakeIssuer + "/token", "jwks_uri": fakeIssuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/keys":
		recorder.Header().Set("Content-Type", "application/json")
		_, _ = recorder.WriteString(`{"keys":[]}`)
	default:
		recorder.WriteHeader(http.StatusNotFound)
	}
	return recorder.Result(), nil
}

func TestMain(m *testing.M) {
	http.DefaultTransport = fakeIssuerTransport{}
	os.Exit(m.Run())
}

type nopSessions struct{ porte.SessionStore }

type nopIdentities struct{ porte.IdentityStore }

type nopCodes struct{ porte.LoginCodeStore }

func mountConfigs() map[string]porte.Config {
	on := porte.Config{
		Issuer: fakeIssuer, ClientID: "app", ClientSecret: "secret",
		RedirectURL: "https://app.test/api/auth/oidc/callback", SuccessURL: "https://app.test/",
	}
	cli := on
	cli.CLIAudience = "facile-cli"
	return map[string]porte.Config{"oidc off": {}, "sso only": {SSOOnly: true}, "oidc on": on, "oidc on with cli": cli}
}

func build(t *testing.T, cfg porte.Config) kit.Config {
	t.Helper()
	manager, err := session.New(cfg, session.Deps{Sessions: nopSessions{}})
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	oidcKit, err := oidc.New(context.Background(), cfg, oidc.Deps{
		Users: &kit.Store{}, Identities: nopIdentities{}, Codes: nopCodes{}, Sessions: manager,
	})
	if err != nil {
		t.Fatalf("oidc kit: %v", err)
	}
	return kit.Config{Sessions: manager, OIDC: oidcKit}
}

func routes(t *testing.T, router chi.Router) []string {
	t.Helper()
	var out []string
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	sort.Strings(out)
	return out
}

func TestMountRegistersExactlyWhatPorteMounts(t *testing.T) {
	for name, cfg := range mountConfigs() {
		t.Run(name, func(t *testing.T) {
			deps := build(t, cfg)
			if deps.OIDC.Enabled() != cfg.Enabled() {
				t.Fatalf("the fake issuer did not enable the kit")
			}
			direct := chi.NewRouter()
			deps.Sessions.Mount(direct)
			deps.OIDC.Mount(direct)
			viaKit := chi.NewRouter()
			if err := kit.Mount(viaKit, deps); err != nil {
				t.Fatalf("mount: %v", err)
			}
			if got, want := routes(t, viaKit), routes(t, direct); !reflect.DeepEqual(got, want) {
				t.Fatalf("kit mounted %v, porte mounts %v", got, want)
			}
		})
	}
}

func TestMountWithoutAnOIDCKitMountsTheSessionRoutesAlone(t *testing.T) {
	deps := build(t, porte.Config{})
	router := chi.NewRouter()
	if err := kit.Mount(router, kit.Config{Sessions: deps.Sessions}); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if got := routes(t, router); !reflect.DeepEqual(got, []string{"POST " + porte.RouteLogout}) {
		t.Fatalf("routes = %v", got)
	}
}

func TestMountRefusesAMissingSessionManager(t *testing.T) {
	if err := kit.Mount(chi.NewRouter(), kit.Config{}); !errors.Is(err, kit.ErrNoSessions) {
		t.Fatalf("err = %v, want ErrNoSessions", err)
	}
}
