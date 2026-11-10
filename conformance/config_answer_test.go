package conformance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacileStudio/porte"
)

type configInput struct {
	Config      map[string]string `json:"config"`
	ConfigExtra map[string]any    `json:"config_extra,omitempty"`
}

func configInputs() map[string]configInput {
	appKeys := map[string]any{"magic_link": true, "sso_only": false, "oidc_enabled": false}
	return map[string]configInput{
		"oidc off":                         {Config: map[string]string{}},
		"oidc off, sso only":               {Config: map[string]string{"SSO_ONLY": "true"}},
		"oidc on implies sso only":         {Config: oidcEnv(nil)},
		"oidc on with sso only":            {Config: oidcEnv(map[string]string{"SSO_ONLY": "true"})},
		"app keys cannot override porte's": {Config: oidcEnv(nil), ConfigExtra: appKeys},
		"app keys with oidc off":           {Config: map[string]string{}, ConfigExtra: map[string]any{"locale": "fr"}},
	}
}

func configAnswer(t *testing.T, in configInput) map[string]any {
	t.Helper()
	var extra func() map[string]any
	if in.ConfigExtra != nil {
		extra = func() map[string]any { return in.ConfigExtra }
	}
	response := newApp(t, in.Config, extra).serve(httptest.NewRequest(http.MethodGet, "http://app.test"+porte.RouteConfig, nil))
	return map[string]any{
		"status":       response.Code,
		"content_type": response.Header().Get("Content-Type"),
		"body":         body(response),
	}
}

func TestConfigAnswerVector(t *testing.T) {
	var cases []testCase
	for _, name := range sortedKeys(configInputs()) {
		in := configInputs()[name]
		cases = append(cases, testCase{Name: name, Input: in, Want: configAnswer(t, in)})
	}
	pin(t, "config_answer", nil, cases)
}
