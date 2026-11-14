package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
)

const mobileRedirect = "dev.facile.app:/auth/callback"

const mobileVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func withMobileRedirect(cfg *porte.Config) { cfg.MobileRedirect = mobileRedirect }

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mobileQuery(challenge string) string {
	return "?" + porte.FlowParam + "=" + porte.FlowMobile +
		"&" + porte.ChallengeParam + "=" + challenge + "&state=abc_123"
}

func mobileCode(t *testing.T, h *harness, query string) (*http.Response, string) {
	t.Helper()
	callback := h.login(t, h.client(t), query)
	if callback.StatusCode != http.StatusFound {
		t.Fatalf("mobile callback = %d, want 302", callback.StatusCode)
	}
	redirect, err := url.Parse(callback.Header.Get("Location"))
	if err != nil {
		t.Fatalf("unparseable redirect: %v", err)
	}
	return callback, redirect.Query().Get("code")
}

func exchangeBody(t *testing.T, h *harness, body string) *http.Response {
	t.Helper()
	response, err := http.Post(h.app.URL+porte.RouteExchange, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST exchange: %v", err)
	}
	closeLater(t, response)
	return response
}

func assertUnknownCode(t *testing.T, response *http.Response) {
	t.Helper()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("exchange = %d, want 401", response.StatusCode)
	}
	var body struct {
		Error struct{ Message string } `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the refusal: %v", err)
	}
	if body.Error.Message != "invalid or expired code" {
		t.Errorf("message = %q, want the unknown-code message", body.Error.Message)
	}
}

func TestMobileLoginHappyPath(t *testing.T) {
	h := newHarness(t, withMobileRedirect)
	callback, code := mobileCode(t, h, mobileQuery(challengeOf(mobileVerifier)))
	if code == "" {
		t.Fatal("the redirect carries no code")
	}
	redirect, _ := url.Parse(callback.Header.Get("Location"))
	if redirect.Scheme != "dev.facile.app" || redirect.Query().Get("state") != "abc_123" {
		t.Fatalf("redirect = %q, want the app scheme echoing state", redirect)
	}

	response := exchangeBody(t, h, fmt.Sprintf(`{"code":%q,"verifier":%q}`, code, mobileVerifier))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exchange = %d, want 200", response.StatusCode)
	}
	var exchanged porte.ExchangeResponse
	if err := json.NewDecoder(response.Body).Decode(&exchanged); err != nil || exchanged.Token == "" {
		t.Fatalf("exchange response = %+v, %v; want a token", exchanged, err)
	}
	assertNotBrowserToken(t, exchanged.Token)
	whose := whoami(t, h, exchanged.Token)
	closeLater(t, whose)
	if whose.StatusCode != http.StatusOK {
		t.Fatalf("the minted token answered %d, want 200", whose.StatusCode)
	}
}

func TestMobileCodeWithoutVerifierIsUnknown(t *testing.T) {
	h := newHarness(t, withMobileRedirect)
	_, code := mobileCode(t, h, mobileQuery(challengeOf(mobileVerifier)))
	assertUnknownCode(t, exchangeBody(t, h, fmt.Sprintf(`{"code":%q}`, code)))
}

func TestMobileCodeWithWrongVerifierIsUnknown(t *testing.T) {
	h := newHarness(t, withMobileRedirect)
	_, code := mobileCode(t, h, mobileQuery(challengeOf(mobileVerifier)))
	assertUnknownCode(t, exchangeBody(t, h, fmt.Sprintf(`{"code":%q,"verifier":"not-the-verifier"}`, code)))
	response := exchangeBody(t, h, fmt.Sprintf(`{"code":%q,"verifier":%q}`, code, mobileVerifier))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("a failed guess burned the code: %d, want 200", response.StatusCode)
	}
}

func TestMobileLoginRefusesABadChallenge(t *testing.T) {
	h := newHarness(t, withMobileRedirect)
	for name, challenge := range map[string]string{
		"missing":    "",
		"short":      "abc",
		"too long":   challengeOf(mobileVerifier) + "A",
		"not base64": strings.Repeat("*", 43),
		"padded":     challengeOf(mobileVerifier)[:42] + "=",
	} {
		t.Run(name, func(t *testing.T) {
			response, err := h.client(t).Get(h.app.URL + porte.RouteLogin + mobileQuery(challenge))
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if location := response.Header.Get("Location"); !strings.Contains(location, "error=") {
				t.Fatalf("Location = %q, want a failure redirect", location)
			}
		})
	}
}

func TestMobileFlowIsRefusedWithoutAConfiguredRedirect(t *testing.T) {
	h := newHarness(t, nil)
	response, err := h.client(t).Get(h.app.URL + porte.RouteLogin + mobileQuery(challengeOf(mobileVerifier)))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if location := response.Header.Get("Location"); !strings.Contains(location, "error=") {
		t.Fatalf("Location = %q, want a failure redirect", location)
	}
}

func TestMobileRedirectIgnoresRequestParameters(t *testing.T) {
	h := newHarness(t, withMobileRedirect)
	query := mobileQuery(challengeOf(mobileVerifier)) +
		"&redirect_uri=https://evil.example&redirect=https://evil.example&port=9999"
	callback, _ := mobileCode(t, h, query)
	redirect, _ := url.Parse(callback.Header.Get("Location"))
	if got := redirect.Scheme + ":" + redirect.Path; got != mobileRedirect {
		t.Fatalf("redirect = %q, want %q", got, mobileRedirect)
	}
}

func TestMobileRedirectConfigValidation(t *testing.T) {
	for value, ok := range map[string]bool{
		"dev.facile.app:/auth":      true,
		"https://app.example/cb":    true,
		"http://app.example/cb":     false,
		"/relative":                 false,
		"dev.facile.app:/auth#frag": false,
		"javascript:alert(1)":       false,
		"https:///nohost":           false,
	} {
		cfg := porte.Config{
			Issuer: "https://idp.example", ClientID: "c", ClientSecret: "s",
			RedirectURL: "https://a.example/cb", SuccessURL: "https://a.example/",
			MobileRedirect: value,
		}
		if err := cfg.Validate(); (err == nil) != ok {
			t.Errorf("%q: Validate() = %v, want ok=%v", value, err, ok)
		}
	}
}

func TestMobileExchangeRefusesAVerifierOutsideRFC7636(t *testing.T) {
	for name, verifier := range map[string]string{
		"too short":   "short",
		"too long":    strings.Repeat("a", 129),
		"bad charset": strings.Repeat("a", 42) + "!",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withMobileRedirect)
			_, code := mobileCode(t, h, mobileQuery(challengeOf(verifier)))
			assertUnknownCode(t, exchangeBody(t, h, fmt.Sprintf(`{"code":%q,"verifier":%q}`, code, verifier)))
		})
	}
}
