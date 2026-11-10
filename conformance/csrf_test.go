package conformance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacileStudio/porte"
)

type csrfInput struct {
	Method        string `json:"method"`
	Transport     string `json:"transport"`
	HeaderPresent bool   `json:"header_present"`
	HeaderValue   string `json:"header_value,omitempty"`
}

func csrfStatus(t *testing.T, in csrfInput) map[string]any {
	t.Helper()
	server := newApp(t, map[string]string{}, nil)
	valid := server.issue(t, userID)
	r := httptest.NewRequest(in.Method, "http://app.test/probe", nil)
	switch in.Transport {
	case "cookie":
		r.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: valid})
	case "bearer":
		r.Header.Set("Authorization", "Bearer "+valid)
	case "unknown_cookie":
		r.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: "not-a-session"})
	case "unknown_bearer":
		r.Header.Set("Authorization", "Bearer not-a-session")
	case "cookie_and_unknown_bearer":
		r.AddCookie(&http.Cookie{Name: porte.SessionCookieName, Value: valid})
		r.Header.Set("Authorization", "Bearer not-a-session")
	}
	if in.HeaderPresent {
		r.Header.Set(porte.CSRFHeaderName, in.HeaderValue)
	}
	response := server.serve(r)
	return map[string]any{
		"status": response.Code, "body": body(response), "set_cookie": response.Header().Values("Set-Cookie"),
	}
}

func csrfInputs() map[string]csrfInput {
	inputs := map[string]csrfInput{
		"no credential":                       {Method: http.MethodGet, Transport: "none"},
		"unknown cookie":                      {Method: http.MethodGet, Transport: "unknown_cookie"},
		"unknown bearer":                      {Method: http.MethodPost, Transport: "unknown_bearer"},
		"cookie wins over a bearer":           {Method: http.MethodGet, Transport: "cookie_and_unknown_bearer"},
		"cookie first, so the header applies": {Method: http.MethodPost, Transport: "cookie_and_unknown_bearer"},
		"empty header value does not count": {
			Method: http.MethodPost, Transport: "cookie", HeaderPresent: true, HeaderValue: "",
		},
	}
	methods := []string{
		http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
	}
	for _, method := range methods {
		for _, transport := range []string{"cookie", "bearer"} {
			inputs[method+" "+transport+" without header"] = csrfInput{Method: method, Transport: transport}
			inputs[method+" "+transport+" with header"] = csrfInput{
				Method: method, Transport: transport, HeaderPresent: true, HeaderValue: "1",
			}
		}
	}
	return inputs
}

func TestCSRFVector(t *testing.T) {
	var cases []testCase
	for _, name := range sortedKeys(csrfInputs()) {
		in := csrfInputs()[name]
		cases = append(cases, testCase{Name: name, Input: in, Want: csrfStatus(t, in)})
	}
	requireFailing(t, cases, func(c testCase) bool { return c.Want.(map[string]any)["status"] == http.StatusForbidden })
	pin(t, "csrf", map[string]any{"header": porte.CSRFHeaderName, "route": "a route behind RequireAuth that answers 200"}, cases)
}
