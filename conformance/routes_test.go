package conformance

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
)

type routeInput struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Config map[string]string `json:"config"`
}

func routeConfigs() map[string]map[string]string {
	return map[string]map[string]string{
		"oidc off":           {},
		"oidc off, sso only": {"SSO_ONLY": "true"},
		"oidc on":            oidcEnv(nil),
		"oidc on with cli":   oidcEnv(map[string]string{"OIDC_CLI_AUDIENCE": cliClient}),
	}
}

func probes() [][2]string {
	return [][2]string{
		{http.MethodGet, porte.RouteConfig},
		{http.MethodPost, porte.RouteConfig},
		{http.MethodGet, porte.RouteLogin},
		{http.MethodGet, porte.RouteLogin + "?flow=cli&port=8765"},
		{http.MethodGet, porte.RouteLogin + "?flow=mobile"},
		{http.MethodGet, porte.RouteCallback},
		{http.MethodPost, porte.RouteExchange},
		{http.MethodPost, porte.RouteDeviceExchange},
		{http.MethodPost, porte.RouteLogout},
		{http.MethodGet, porte.RouteLogout},
		{http.MethodPost, porte.RouteSyncProfile},
		{http.MethodPost, porte.RouteBackchannelLogout},
		{http.MethodPost, porte.RouteRegister},
		{http.MethodPost, porte.RouteLoginLocal},
	}
}

func location(header string) any {
	if header == "" {
		return nil
	}
	target, err := url.Parse(header)
	if err != nil || !target.Query().Has("state") {
		return map[string]any{"url": header}
	}
	keys := sortedKeys(target.Query())
	target.RawQuery = ""
	return map[string]any{"url": target.String(), "query_keys": keys}
}

func routeAnswer(t *testing.T, server app, in routeInput) map[string]any {
	t.Helper()
	r := httptest.NewRequest(in.Method, "http://app.test"+in.Path, nil)
	response := server.serve(r)
	want := map[string]any{"status": response.Code, "location": location(response.Header().Get("Location"))}
	switch response.Code {
	case http.StatusFound, http.StatusMethodNotAllowed, http.StatusNotFound:
	default:
		want["body"] = body(response)
	}
	var cookies []string
	for _, header := range response.Header().Values("Set-Cookie") {
		cookies = append(cookies, redactValue(header))
	}
	want["set_cookie"] = cookies
	return want
}

func redactValue(header string) string {
	name, rest, _ := strings.Cut(header, "=")
	_, attributes, _ := strings.Cut(rest, ";")
	return name + "=<value>;" + attributes
}

func TestRoutesVector(t *testing.T) {
	var cases []testCase
	configs := routeConfigs()
	for _, configName := range sortedKeys(configs) {
		server := newApp(t, configs[configName], nil)
		for _, probe := range probes() {
			in := routeInput{Method: probe[0], Path: probe[1], Config: configs[configName]}
			cases = append(cases, testCase{
				Name:  configName + ": " + probe[0] + " " + probe[1],
				Input: in,
				Want:  routeAnswer(t, server, in),
			})
		}
	}
	requireFailing(t, cases, func(c testCase) bool { return c.Want.(map[string]any)["status"] == http.StatusNotFound })
	pin(t, "routes", map[string]any{"issuer": issuer, "discovery": discovery()}, cases)
}
