package conformance

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
)

const (
	logoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	otherUserID = 8
	formType    = "application/x-www-form-urlencoded"
)

type logoutInput struct {
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

func logoutClaims(changes map[string]any) map[string]any {
	claims := map[string]any{
		"iss": issuer, "sub": userSubject, "aud": clientID, "iat": longAgo, "exp": farFuture,
		"jti": "logout-1", "events": map[string]any{logoutEvent: map[string]any{}},
	}
	for key, value := range changes {
		if value == nil {
			delete(claims, key)
			continue
		}
		claims[key] = value
	}
	return claims
}

func logoutForm(token string) logoutInput {
	return logoutInput{ContentType: formType, Body: "logout_token=" + url.QueryEscape(token)}
}

func logoutInputs(t *testing.T) map[string]logoutInput {
	t.Helper()
	return map[string]logoutInput{
		"revokes every session of the subject":          logoutForm(sign(t, logoutClaims(nil))),
		"unknown subject is a 200 that deletes nothing": logoutForm(sign(t, logoutClaims(map[string]any{"sub": "nobody"}))),
		"a nonce is refused":                            logoutForm(sign(t, logoutClaims(map[string]any{"nonce": "n"}))),
		"no events claim":                               logoutForm(sign(t, logoutClaims(map[string]any{"events": nil}))),
		"another event":                                 logoutForm(sign(t, logoutClaims(map[string]any{"events": map[string]any{"x": map[string]any{}}}))),
		"events is not an object":                       logoutForm(sign(t, logoutClaims(map[string]any{"events": "logout"}))),
		"no subject":                                    logoutForm(sign(t, logoutClaims(map[string]any{"sub": nil}))),
		"wrong audience":                                logoutForm(sign(t, logoutClaims(map[string]any{"aud": "other-app"}))),
		"wrong issuer":                                  logoutForm(sign(t, logoutClaims(map[string]any{"iss": "https://evil.test"}))),
		"expired":                                       logoutForm(sign(t, logoutClaims(map[string]any{"exp": longAgo}))),
		"signed by another key":                         logoutForm(signWith(t, provider.rogue, map[string]any{"alg": "RS256", "kid": keyID}, logoutClaims(nil))),
		"not a JWT":                                     logoutForm("opaque"),
		"missing logout_token":                          {ContentType: formType, Body: "other=1"},
		"a JSON body is not a form":                     {ContentType: "application/json", Body: `{"logout_token":"x"}`},
		"malformed form":                                {ContentType: formType, Body: "logout_token=%zz"},
	}
}

func logout(t *testing.T, in logoutInput) map[string]any {
	t.Helper()
	server := newApp(t, oidcEnv(nil), nil)
	server.issue(t, userID)
	server.issue(t, userID)
	server.issue(t, otherUserID)
	r := httptest.NewRequest(http.MethodPost, "http://app.test"+porte.RouteBackchannelLogout, strings.NewReader(in.Body))
	r.Header.Set("Content-Type", in.ContentType)
	response := server.serve(r)
	return map[string]any{
		"status":                   response.Code,
		"body":                     body(response),
		"cache_control":            response.Header().Get("Cache-Control"),
		"sessions_deleted":         2 - server.sessions.count(userID),
		"other_user_sessions_left": server.sessions.count(otherUserID),
	}
}

func TestBackchannelLogoutVector(t *testing.T) {
	inputs := logoutInputs(t)
	var cases []testCase
	for _, name := range sortedKeys(inputs) {
		cases = append(cases, testCase{Name: name, Input: inputs[name], Want: logout(t, inputs[name])})
	}
	requireFailing(t, cases, func(c testCase) bool { return c.Want.(map[string]any)["status"] == http.StatusUnauthorized })
	pin(t, "backchannel_logout", map[string]any{
		"issuer": issuer, "client_id": clientID, "clock": "wall clock; every token is issued at 1600000000 and expires at 4102444800 unless the case says otherwise", "known_subject": userSubject,
		"sessions":  map[string]int{"subject_user": 2, "other_user": 1},
		"discovery": discovery(), "jwks": provider.jwks(), "event": logoutEvent,
	}, cases)
}
