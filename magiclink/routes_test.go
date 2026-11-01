package magiclink

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"

	"github.com/go-chi/chi/v5"
)

func post(router http.Handler, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.7:51234"
	router.ServeHTTP(w, request)
	return w
}

func mounted(t *testing.T) (*chi.Mux, *rig) {
	t.Helper()
	r := newRig(t, Config{})
	router := chi.NewRouter()
	r.kit.Mount(router)
	return router, r
}

func TestTheRequestRouteAnswersTheSameForAnyAddress(t *testing.T) {
	router, r := mounted(t)
	known := post(router, porte.RouteMagicLink, `{"email":"camille@facile.studio"}`)
	unknown := post(router, porte.RouteMagicLink, `{"email":"nobody@facile.studio"}`)
	r.kit.Wait()

	if known.Code != http.StatusAccepted || unknown.Code != known.Code || unknown.Body.String() != known.Body.String() {
		t.Fatalf("known %d %q, unknown %d %q", known.Code, known.Body, unknown.Code, unknown.Body)
	}
	var body porte.MagicLinkRequestResponse
	if err := json.Unmarshal(known.Body.Bytes(), &body); err != nil || !body.OK {
		t.Fatalf("body %q: %v", known.Body, err)
	}
	if r.links.created[0].IP != "192.0.2.7" {
		t.Fatalf("the source address was %q, want the host without the port", r.links.created[0].IP)
	}
}

func TestTheConsumeRouteSignsInAndNeverOnGet(t *testing.T) {
	router, r := mounted(t)
	post(router, porte.RouteMagicLink, `{"email":"camille@facile.studio"}`)
	r.kit.Wait()
	token := r.mail.token(t)

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, porte.RouteMagicLinkConsume+"?token="+token, nil))
	if get.Code != http.StatusMethodNotAllowed || r.sessions.issued() != 0 {
		t.Fatalf("a GET must not sign in: status %d, %d sessions", get.Code, r.sessions.issued())
	}

	w := post(router, porte.RouteMagicLinkConsume, `{"token":"`+token+`"}`)
	var body porte.ExchangeResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.UserID != "1" || body.Token == "" {
		t.Fatalf("consume: %d %q", w.Code, w.Body)
	}
	if len(w.Result().Cookies()) == 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("consume must set the session cookie and forbid caching")
	}
	if again := post(router, porte.RouteMagicLinkConsume, `{"token":"`+token+`"}`); again.Code != http.StatusUnauthorized {
		t.Fatalf("a replay answers %d, want 401", again.Code)
	}
}
