package porte_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

func lookup(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func fullEnv() map[string]string {
	return map[string]string{
		"OIDC_ISSUER":           "https://sso.facile.studio",
		"OIDC_CLIENT_ID":        "agenda",
		"OIDC_CLIENT_SECRET":    " secret\n",
		"OIDC_REDIRECT_URL":     "https://agenda.facile.studio/api/auth/oidc/callback",
		"OIDC_SUCCESS_URL":      "https://agenda.facile.studio/",
		"OIDC_FAILURE_URL":      "https://agenda.facile.studio/login",
		"OIDC_MOBILE_REDIRECT":  "studio.facile.agenda://auth",
		"OIDC_APP_NAME":         "Agenda",
		"OIDC_LOGO_URL":         "https://agenda.facile.studio/logo.svg",
		"OIDC_CLAIMS_SCOPE":     "roles",
		"OIDC_MACHINE_AUDIENCE": "agenda",
		"OIDC_SCOPE_PREFIX":     "agenda",
		"OIDC_CLI_AUDIENCE":     "facile-cli",
		"SSO_ONLY":              "true",
	}
}

func TestConfigFromEnvReadsEverySuiteVariable(t *testing.T) {
	got, err := porte.ConfigFromEnv(lookup(fullEnv()), porte.Config{})
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	want := porte.Config{
		Issuer:          "https://sso.facile.studio",
		ClientID:        "agenda",
		ClientSecret:    "secret",
		RedirectURL:     "https://agenda.facile.studio/api/auth/oidc/callback",
		SuccessURL:      "https://agenda.facile.studio/",
		FailureURL:      "https://agenda.facile.studio/login",
		MobileRedirect:  "studio.facile.agenda://auth",
		AppName:         "Agenda",
		LogoURL:         "https://agenda.facile.studio/logo.svg",
		ClaimsScope:     "roles",
		MachineAudience: "agenda",
		ScopePrefix:     "agenda",
		CLIAudience:     "facile-cli",
		SSOOnly:         true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ConfigFromEnv = %+v\nwant %+v", got, want)
	}
}

func TestConfigFromEnvCoversEveryVariableValidateNames(t *testing.T) {
	read := map[string]bool{}
	_, _ = porte.ConfigFromEnv(func(name string) string { read[name] = true; return "" }, porte.Config{})
	for name := range fullEnv() {
		if !read[name] {
			t.Errorf("%s is never read", name)
		}
	}
	if len(read) != len(fullEnv()) {
		t.Errorf("read %d variables, the test table holds %d", len(read), len(fullEnv()))
	}
}

func TestConfigFromEnvNamesEveryMissingVariable(t *testing.T) {
	_, err := porte.ConfigFromEnv(lookup(map[string]string{"OIDC_ISSUER": "https://sso.facile.studio", "OIDC_CLIENT_ID": "agenda"}), porte.Config{})
	if err == nil {
		t.Fatal("a provider with no secret, redirect or success URL was accepted")
	}
	for _, name := range []string{"OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "OIDC_SUCCESS_URL"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}
}

func TestConfigFromEnvWithoutAnIssuerLeavesOIDCOff(t *testing.T) {
	defaults := porte.Config{MobileRedirect: "studio.facile.bulle://auth", SSOOnly: true, SessionTTL: time.Hour}
	got, err := porte.ConfigFromEnv(lookup(nil), defaults)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if got.Enabled() || got.MobileRedirect != "" || !got.SSOOnly || got.SessionTTL != time.Hour {
		t.Fatalf("ConfigFromEnv = %+v, want OIDC off with the other defaults kept", got)
	}
}

func TestConfigFromEnvRefusesAMobileRedirectSetWithoutAnIssuer(t *testing.T) {
	_, err := porte.ConfigFromEnv(lookup(map[string]string{"OIDC_MOBILE_REDIRECT": "studio.facile.bulle://auth"}), porte.Config{})
	if err == nil || !strings.Contains(err.Error(), "OIDC_MOBILE_REDIRECT") {
		t.Fatalf("err = %v, want a refusal naming OIDC_MOBILE_REDIRECT", err)
	}
}

func TestConfigFromEnvPrefersTheEnvironmentOverADefault(t *testing.T) {
	env := fullEnv()
	delete(env, "OIDC_SUCCESS_URL")
	delete(env, "SSO_ONLY")
	defaults := porte.Config{
		SuccessURL: "https://first-cors-origin.test", MobileRedirect: "studio.facile.other://auth",
		SSOOnly: true, ExtraScopes: []string{"connections"},
	}
	got, err := porte.ConfigFromEnv(lookup(env), defaults)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if got.SuccessURL != "https://first-cors-origin.test" || !got.SSOOnly {
		t.Errorf("unset variables did not fall back to the defaults: %+v", got)
	}
	if got.MobileRedirect != "studio.facile.agenda://auth" || len(got.ExtraScopes) != 1 {
		t.Errorf("a set variable lost to its default, or a field with no variable was dropped: %+v", got)
	}
}

func TestConfigFromEnvRefusesAnSSOOnlyThatIsNotABoolean(t *testing.T) {
	_, err := porte.ConfigFromEnv(lookup(map[string]string{"SSO_ONLY": "yes please"}), porte.Config{})
	if err == nil || !strings.Contains(err.Error(), "SSO_ONLY") {
		t.Fatalf("err = %v, want a refusal naming SSO_ONLY", err)
	}
}

func TestConfigFromEnvReadsTheProcessEnvironmentByDefault(t *testing.T) {
	for name, value := range fullEnv() {
		t.Setenv(name, value)
	}
	got, err := porte.ConfigFromEnv(nil, porte.Config{})
	if err != nil || got.ClientID != "agenda" {
		t.Fatalf("porte.ConfigFromEnv(nil) = %+v, %v", got, err)
	}
}
