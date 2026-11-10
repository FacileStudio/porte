package conformance

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"
)

type cookieInput struct {
	Action         string `json:"action"`
	TLS            bool   `json:"tls"`
	ForwardedProto string `json:"forwarded_proto"`
	RedirectURL    string `json:"redirect_url"`
	TTLSeconds     int    `json:"ttl_seconds"`
	AcceptLegacy   bool   `json:"accept_legacy_cookie"`
	Cookie         string `json:"cookie_header,omitempty"`
}

func cookieManager(t *testing.T, in cookieInput) *session.Manager {
	t.Helper()
	manager, err := session.New(porte.Config{
		RedirectURL:        in.RedirectURL,
		SessionTTL:         time.Duration(in.TTLSeconds) * time.Second,
		AcceptLegacyCookie: in.AcceptLegacy,
	}, session.Deps{Sessions: newSessions()})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}
	return manager
}

func cookieRequest(in cookieInput) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	if in.TLS {
		r.TLS = &tls.ConnectionState{}
	}
	if in.ForwardedProto != "" {
		r.Header.Set("X-Forwarded-Proto", in.ForwardedProto)
	}
	if in.Cookie != "" {
		r.Header.Set("Cookie", in.Cookie)
	}
	return r
}

func runCookie(t *testing.T, in cookieInput) any {
	t.Helper()
	manager := cookieManager(t, in)
	r := cookieRequest(in)
	recorder := httptest.NewRecorder()
	switch in.Action {
	case "set":
		manager.SetSessionCookie(recorder, r, "TOKEN")
	case "clear":
		manager.ClearCookie(recorder, r, porte.SessionCookieName)
	default:
		value, found := manager.ReadCookie(r, porte.SessionCookieName)
		return map[string]any{"found": found, "value": value}
	}
	return map[string]any{"set_cookie": recorder.Result().Header.Values("Set-Cookie")}
}

func cookieInputs() map[string]cookieInput {
	https := "https://app.test/api/auth/oidc/callback"
	return map[string]cookieInput{
		"set over plain http":                   {Action: "set"},
		"set behind a TLS proxy":                {Action: "set", ForwardedProto: "https"},
		"set with forwarded proto in caps":      {Action: "set", ForwardedProto: "HTTPS"},
		"set over direct TLS":                   {Action: "set", TLS: true},
		"set when the config is https":          {Action: "set", RedirectURL: https},
		"set with forwarded http, config https": {Action: "set", ForwardedProto: "http", RedirectURL: https},
		"set with a one hour ttl":               {Action: "set", ForwardedProto: "https", TTLSeconds: 3600},
		"clear over plain http":                 {Action: "clear"},
		"clear over https expires both names":   {Action: "clear", ForwardedProto: "https"},
		"read the bare name over http":          {Action: "read", Cookie: "session=abc"},
		"read ignores __Host- over http":        {Action: "read", Cookie: "__Host-session=abc"},
		"read the prefixed name over https":     {Action: "read", ForwardedProto: "https", Cookie: "__Host-session=abc"},
		"read refuses the bare name over https": {Action: "read", ForwardedProto: "https", Cookie: "session=abc"},
		"read the legacy name when accepted": {
			Action: "read", ForwardedProto: "https", AcceptLegacy: true, Cookie: "session=old",
		},
		"read prefers the prefixed name": {
			Action: "read", ForwardedProto: "https", AcceptLegacy: true, Cookie: "session=old; __Host-session=new",
		},
		"read skips an empty value": {Action: "read", Cookie: "session="},
	}
}

func TestCookieVector(t *testing.T) {
	var cases []testCase
	for _, name := range sortedKeys(cookieInputs()) {
		in := cookieInputs()[name]
		cases = append(cases, testCase{Name: name, Input: in, Want: runCookie(t, in)})
	}
	pin(t, "cookie", map[string]any{"name": porte.SessionCookieName, "host_prefix": "__Host-"}, cases)
}
