package oidc

import "testing"

// TestTheLocaleClaimReachesTheStoreNormalised walks a real callback per
// shape: a regional tag, an unsupported language, no claim, and a non-string
// that must not fail the login.
func TestTheLocaleClaimReachesTheStoreNormalised(t *testing.T) {
	cases := []struct {
		claim any
		want  string
	}{
		{"fr-FR", "fr"}, {"de_CH", "de"}, {"es", "es"}, {"it-IT", "en"}, {nil, "en"}, {42, "en"},
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
