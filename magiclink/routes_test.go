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

func postWith(router http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.RemoteAddr = "192.0.2.7:51234"
	router.ServeHTTP(w, request)
	return w
}

func post(router http.Handler, path, body string) *httptest.ResponseRecorder {
	return postWith(router, path, body, map[string]string{porte.CSRFHeaderName: "1"})
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

func TestConsumeWithoutTheCSRFHeaderIsRefusedAndSpendsNothing(t *testing.T) {
	router, r := mounted(t)
	post(router, porte.RouteMagicLink, `{"email":"camille@facile.studio"}`)
	r.kit.Wait()
	token := r.mail.token(t)
	body := `{"token":"` + token + `"}`

	forged := postWith(router, porte.RouteMagicLinkConsume, body, nil)
	if forged.Code != http.StatusForbidden || len(forged.Result().Cookies()) != 0 || r.sessions.issued() != 0 {
		t.Fatalf("a cross-site post must be refused before it signs anyone in: %d, %d sessions", forged.Code, r.sessions.issued())
	}
	if ok := post(router, porte.RouteMagicLinkConsume, body); ok.Code != http.StatusOK {
		t.Fatalf("the forged request spent the link: %d", ok.Code)
	}
}

func TestTheSourceAddressIsRemoteAddrUnlessTheAppResolvesIt(t *testing.T) {
	r := newRig(t, Config{ClientIP: func(*http.Request) string { return "203.0.113.5" }})
	router := chi.NewRouter()
	r.kit.Mount(router)
	post(router, porte.RouteMagicLink, `{"email":"camille@facile.studio"}`)
	r.kit.Wait()
	if got := r.links.created[0].IP; got != "203.0.113.5" {
		t.Fatalf("stored %q, want the resolved address", got)
	}

	plain, other := mounted(t)
	post(plain, porte.RouteMagicLink, `{"email":"camille@facile.studio"}`)
	postWith(plain, porte.RouteMagicLink, `{"email":"dana@facile.studio"}`, map[string]string{"X-Forwarded-For": "198.51.100.1"})
	other.kit.Wait()
	for _, link := range other.links.created {
		if link.IP != "192.0.2.7" {
			t.Fatalf("X-Forwarded-For was trusted: stored %q", link.IP)
		}
	}
}
