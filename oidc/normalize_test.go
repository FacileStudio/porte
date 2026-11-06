package oidc

import (
	"net/url"
	"testing"

	"github.com/FacileStudio/porte"
)

// TestTheLocaleClaimReachesTheStoreNormalised walks a real callback per
// shape: a regional tag, an unsupported language, no claim, and a non-string
// that must not fail the login.
func TestTheLocaleClaimReachesTheStoreNormalised(t *testing.T) {
	cases := []struct {
		claim any
		want  string
	}{
		{"fr-FR", "fr"}, {"de_CH", "de"}, {"es", "es"}, {"it-IT", "en"}, {nil, ""}, {42, ""},
	}
	for _, c := range cases {
		h := newHarness(t, nil)
		h.idp.mintClaims = func(claims map[string]any) {
			if c.claim != nil {
				claims["locale"] = c.claim
			}
		}
		if got := h.login(t, h.client(t), "").Header.Get("Location"); got != h.app.URL+"/welcome" {
			t.Fatalf("locale %v: the login was refused (%q)", c.claim, got)
		}
		h.stores.mu.Lock()
		locale := h.stores.lastClaims.Locale
		h.stores.mu.Unlock()
		if locale != c.want {
			t.Errorf("locale %v reached the store as %q, want %q", c.claim, locale, c.want)
		}
	}
}

// TestTheEmailClaimReachesTheStoreLowercased pins that the address an
// account is matched on is spelled the way porte/local spells it.
func TestTheEmailClaimReachesTheStoreLowercased(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.mintClaims = func(claims map[string]any) { claims["email"] = " Case@Example.TEST " }
	if got := h.login(t, h.client(t), "").Header.Get("Location"); got != h.app.URL+"/welcome" {
		t.Fatalf("the login was refused (%q)", got)
	}
	h.stores.mu.Lock()
	email := h.stores.lastClaims.Email
	h.stores.mu.Unlock()
	if email != "case@example.test" {
		t.Errorf("the address reached the store as %q", email)
	}
}

// TestTheSignInLanguageReachesTheProvider pins the forward and the filter:
// one of the four languages passes, anything else never reaches the URL.
func TestTheSignInLanguageReachesTheProvider(t *testing.T) {
	h := newHarness(t, nil)
	client := h.client(t)
	cases := map[string]string{"fr": "fr", "DE": "de", " es ": "es", "it": "", "fr de": "", "fr-FR": "", "": "", "<x>": ""}
	for sent, want := range cases {
		response, err := client.Get(h.app.URL + porte.RouteLogin + "?" + url.Values{porte.UILocalesParam: {sent}}.Encode())
		if err != nil {
			t.Fatalf("GET login: %v", err)
		}
		_ = response.Body.Close()
		location, err := url.Parse(response.Header.Get("Location"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := location.Query().Get("ui_locales"); got != want || (want == "" && location.Query().Has("ui_locales")) {
			t.Errorf("ui_locales %q reached the provider as %q, want %q", sent, got, want)
		}
	}
}
