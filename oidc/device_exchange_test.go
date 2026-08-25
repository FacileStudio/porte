package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

// withMachineAudience is what an operator sets to turn the device exchange on:
// the audience Registre stamps on a token minted for the official CLI. Nothing
// else enables the route.
func withMachineAudience(cfg *porte.Config) { cfg.MachineAudience = "test-client" }

// closeLater closes a response body when the test ends, and complains if it
// cannot, because a discarded Close is where a leaked connection hides.
func closeLater(t *testing.T, response *http.Response) {
	t.Helper()
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("closing the response body: %v", err)
		}
	})
}

// deviceExchange posts body to the exchange route exactly as the CLI does,
// with no credential of any kind attached: no cookie, no Authorization header,
// no CSRF header. The token in the body is the whole request.
func deviceExchange(t *testing.T, h *harness, body string) *http.Response {
	t.Helper()
	response, err := h.app.Client().Post(
		h.app.URL+porte.RouteDeviceExchange, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", porte.RouteDeviceExchange, err)
	}
	closeLater(t, response)
	return response
}

// deviceRefusals is the refusal matrix for a request that is well-formed JSON
// carrying a well-formed field: ten ways to hold something token-shaped and
// still not be signed in. Every one of them must answer the same 401. Which
// check failed is not the caller's business, and the last two would otherwise
// tell a stranger whether a given subject has an account here.
func deviceRefusals(h *harness) map[string]string {
	good := h.idp.accessToken()
	mutated := func(claim string, value any) string {
		return h.idp.accessTokenWith(func(claims map[string]any) { claims[claim] = value })
	}
	return map[string]string{
		"not a token at all":         "not-a-jwt",
		"three segments of nonsense": "aaa.bbb.ccc",
		"tampered signature":         good[:len(good)-4] + "AAAA",
		"unknown kid": signJWT(h.idp.key, "rotated-out", map[string]any{
			"iss": h.idp.issuer(), "sub": h.idp.subject, "aud": "test-client",
			"exp": time.Now().Add(time.Minute).Unix(),
		}),
		"wrong audience":                 mutated("aud", "some-other-client"),
		"wrong issuer":                   mutated("iss", "https://evil.example"),
		"expired":                        mutated("exp", time.Now().Add(-time.Hour).Unix()),
		"not valid yet":                  mutated("nbf", time.Now().Add(time.Hour).Unix()),
		"no subject":                     mutated("sub", ""),
		"a subject with no account here": mutated("sub", "stranger"),
	}
}

// TestTheDeviceExchangeMintsThisAppsOwnSession is the endpoint's reason to
// exist. The CLI runs the device grant once against Registre and trades the
// single access token it gets for each tool's own credential, because writing
// the provider's token into the slot where a CLI keeps its session is a login
// that stops working when that token expires.
//
// So the assertion is not merely "200 with a token". It is that the token in
// the response is porte's own and works as one on a route the provider's token
// was never issued for.
func TestTheDeviceExchangeMintsThisAppsOwnSession(t *testing.T) {
	h := newHarness(t, withMachineAudience)
	saveIdentity(t, h.stores, h.idp.issuer(), h.idp.subject, 7)
	accessToken := h.idp.accessToken()

	response := deviceExchange(t, h, fmt.Sprintf(`{"access_token":%q}`, accessToken))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("a valid registre token answered %d, want 200", response.StatusCode)
	}
	if store := response.Header.Get("Cache-Control"); store != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on a response carrying a credential", store)
	}
	var body porte.ExchangeResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the exchange response: %v", err)
	}
	if body.Token == "" || body.Token == accessToken {
		t.Fatalf("token = %q, want this app's own session rather than the provider's token", body.Token)
	}
	if body.UserID != "7" {
		t.Errorf("user_id = %q, want the local account the subject resolves to", body.UserID)
	}
	whose := whoami(t, h, body.Token)
	closeLater(t, whose)
	if whose.StatusCode != http.StatusOK {
		t.Fatalf("the minted session answered %d on an authenticated route, want 200", whose.StatusCode)
	}
}

// TestEveryDeviceRefusalAnswersTheSame401 walks the matrix. A suite that only
// proves acceptance is how an auth bypass ships green, and one that proves
// distinguishable refusals ships an account-enumeration oracle instead, so
// both halves are asserted here.
func TestEveryDeviceRefusalAnswersTheSame401(t *testing.T) {
	h := newHarness(t, withMachineAudience)
	saveIdentity(t, h.stores, h.idp.issuer(), h.idp.subject, 7)

	for name, token := range deviceRefusals(h) {
		t.Run(name, func(t *testing.T) {
			response := deviceExchange(t, h, fmt.Sprintf(`{"access_token":%q}`, token))
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("answered %d, want 401", response.StatusCode)
			}
			var body struct {
				Error struct{ Message string } `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatalf("decoding the refusal: %v", err)
			}
			if body.Error.Message != "invalid access token" {
				t.Errorf("message = %q, want the one every refusal shares", body.Error.Message)
			}
		})
	}
}

// TestAMalformedDeviceExchangeIsRefusedOnItsMerits pins the half of the
// contract that is about the status code rather than the credential. The CLI
// probes this route with a POST carrying an empty body and reads 404 as "this
// app has not shipped the exchange", so a mounted route must refuse a bad
// request on its merits, and 400 is the only honest answer to a body with no
// token in it.
func TestAMalformedDeviceExchangeIsRefusedOnItsMerits(t *testing.T) {
	h := newHarness(t, withMachineAudience)

	for name, body := range map[string]string{
		"the CLI's probe": "",
		"no field":        `{}`,
		"empty field":     `{"access_token":""}`,
		"not JSON":        `access_token=x`,
	} {
		t.Run(name, func(t *testing.T) {
			if status := deviceExchange(t, h, body).StatusCode; status != http.StatusBadRequest {
				t.Fatalf("answered %d, want 400; a mounted route must never 404", status)
			}
		})
	}
}

// TestTheRouteIsAbsentWithoutAMachineAudience is the deliberate 404. An app
// with no audience to check has no verifier, so it cannot tell a Registre
// token from a forgery and must not pretend to serve the exchange. 404 is
// precisely the signal the CLI reads as "not shipped" before falling back to
// the loopback flow, which makes the absence the correct answer rather than a
// gap.
func TestTheRouteIsAbsentWithoutAMachineAudience(t *testing.T) {
	h := newHarness(t, nil)

	response := deviceExchange(t, h, fmt.Sprintf(`{"access_token":%q}`, h.idp.accessToken()))
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("answered %d, want 404, the CLI's not-shipped signal", response.StatusCode)
	}
}

// TestARemovedIdentityRowEndsTheDeviceExchange is the deactivation lever.
// porte has no disabled flag, and a Registre token carries no session row for
// back-channel logout to revoke, so IdentityStore.Find refusing is the only
// thing an app can do to stop a token that has not expired yet from buying a
// thirty-day session here.
func TestARemovedIdentityRowEndsTheDeviceExchange(t *testing.T) {
	h := newHarness(t, withMachineAudience)
	saveIdentity(t, h.stores, h.idp.issuer(), h.idp.subject, 7)
	body := fmt.Sprintf(`{"access_token":%q}`, h.idp.accessToken())

	if status := deviceExchange(t, h, body).StatusCode; status != http.StatusOK {
		t.Fatalf("a live account answered %d, want 200", status)
	}

	h.stores.mu.Lock()
	delete(h.stores.identities, h.idp.issuer()+"\x00"+h.idp.subject)
	h.stores.mu.Unlock()

	if status := deviceExchange(t, h, body).StatusCode; status != http.StatusUnauthorized {
		t.Fatalf("a deactivated account answered %d, want 401", status)
	}
}

// TestAnIdentityRowNamingNoAccountIsRefused covers the store bug that would
// otherwise mint a session for account zero, the identity of everybody at
// once. No account has that id, so a row carrying it is broken, and both
// callers of VerifyJWT spend the UserID directly.
func TestAnIdentityRowNamingNoAccountIsRefused(t *testing.T) {
	h := newHarness(t, withMachineAudience)
	saveIdentity(t, h.stores, h.idp.issuer(), h.idp.subject, 0)

	response := deviceExchange(t, h, fmt.Sprintf(`{"access_token":%q}`, h.idp.accessToken()))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a row naming account zero answered %d, want 401", response.StatusCode)
	}
}
