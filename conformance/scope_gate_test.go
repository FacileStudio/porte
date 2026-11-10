package conformance

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	farFuture = 4102444800
	longAgo   = 1600000000
)

type scopeInput struct {
	Method     string  `json:"method"`
	Prefix     string  `json:"prefix"`
	ScopeClaim *string `json:"scope_claim"`
	Subject    string  `json:"subject"`
	Token      string  `json:"token"`
}

func gateToken(t *testing.T, subject string, scope *string) string {
	t.Helper()
	claims := map[string]any{"iss": issuer, "sub": subject, "aud": clientID, "exp": farFuture, "iat": longAgo}
	if scope != nil {
		claims["scope"] = *scope
	}
	return sign(t, claims)
}

func gateApps(t *testing.T) map[string]app {
	t.Helper()
	apps := map[string]app{}
	for _, prefix := range []string{"", "app"} {
		apps[prefix] = newApp(t, oidcEnv(map[string]string{
			"OIDC_MACHINE_AUDIENCE": clientID, "OIDC_SCOPE_PREFIX": prefix,
		}), nil)
	}
	return apps
}

func gateInputs(t *testing.T) []scopeInput {
	t.Helper()
	scopes := []*string{nil}
	for _, scope := range []string{"", "app.read", "app.write", "app.read app.write", "other.write", "app.readonly", "APP.WRITE"} {
		scopes = append(scopes, &scope)
	}
	var inputs []scopeInput
	for _, prefix := range []string{"", "app"} {
		inputs = append(inputs, prefixInputs(t, prefix, scopes)...)
		write := "app.write"
		inputs = append(inputs, scopeInput{
			Method: http.MethodGet, Prefix: prefix, ScopeClaim: &write, Subject: "unknown-subject",
			Token: gateToken(t, "unknown-subject", &write),
		})
	}
	return inputs
}

func prefixInputs(t *testing.T, prefix string, scopes []*string) []scopeInput {
	t.Helper()
	var inputs []scopeInput
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete} {
		for _, scope := range scopes {
			inputs = append(inputs, scopeInput{
				Method: method, Prefix: prefix, ScopeClaim: scope, Subject: userSubject,
				Token: gateToken(t, userSubject, scope),
			})
		}
	}
	return inputs
}

func scopeName(in scopeInput) string {
	scope := "no scope claim"
	if in.ScopeClaim != nil {
		scope = "scope " + `"` + *in.ScopeClaim + `"`
	}
	return "prefix " + `"` + in.Prefix + `" ` + in.Method + " " + scope + " sub " + in.Subject
}

func TestScopeGateVector(t *testing.T) {
	apps := gateApps(t)
	var cases []testCase
	for _, in := range gateInputs(t) {
		r := httptest.NewRequest(in.Method, "http://app.test/probe", nil)
		r.Header.Set("Authorization", "Bearer "+in.Token)
		response := apps[in.Prefix].serve(r)
		cases = append(cases, testCase{
			Name: scopeName(in), Input: in,
			Want: map[string]any{"status": response.Code, "body": body(response)},
		})
	}
	requireFailing(t, cases, func(c testCase) bool { return c.Want.(map[string]any)["status"] == http.StatusForbidden })
	pin(t, "scope_gate", map[string]any{
		"issuer": issuer, "machine_audience": clientID, "clock": "wall clock; every token is issued at 1600000000 and expires at 4102444800 unless the case says otherwise", "known_subject": userSubject,
		"discovery": discovery(), "jwks": provider.jwks(), "route": "a route behind RequireAuth that answers 200",
	}, cases)
}
