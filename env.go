package porte

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var envFields = []struct {
	name  string
	field func(*Config) *string
}{
	{"OIDC_ISSUER", func(c *Config) *string { return &c.Issuer }},
	{"OIDC_CLIENT_ID", func(c *Config) *string { return &c.ClientID }},
	{"OIDC_CLIENT_SECRET", func(c *Config) *string { return &c.ClientSecret }},
	{"OIDC_REDIRECT_URL", func(c *Config) *string { return &c.RedirectURL }},
	{"OIDC_SUCCESS_URL", func(c *Config) *string { return &c.SuccessURL }},
	{"OIDC_FAILURE_URL", func(c *Config) *string { return &c.FailureURL }},
	{"OIDC_MOBILE_REDIRECT", func(c *Config) *string { return &c.MobileRedirect }},
	{"OIDC_APP_NAME", func(c *Config) *string { return &c.AppName }},
	{"OIDC_LOGO_URL", func(c *Config) *string { return &c.LogoURL }},
	{"OIDC_CLAIMS_SCOPE", func(c *Config) *string { return &c.ClaimsScope }},
	{"OIDC_MACHINE_AUDIENCE", func(c *Config) *string { return &c.MachineAudience }},
	{"OIDC_SCOPE_PREFIX", func(c *Config) *string { return &c.ScopePrefix }},
	{"OIDC_CLI_AUDIENCE", func(c *Config) *string { return &c.CLIAudience }},
}

// ConfigFromEnv builds a Config from the variables every suite app sets:
// OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URL,
// OIDC_SUCCESS_URL, OIDC_FAILURE_URL, OIDC_MOBILE_REDIRECT, OIDC_APP_NAME,
// OIDC_LOGO_URL, OIDC_CLAIMS_SCOPE, OIDC_MACHINE_AUDIENCE, OIDC_SCOPE_PREFIX,
// OIDC_CLI_AUDIENCE and SSO_ONLY.
//
// get reads one variable, os.Getenv in an app and a map lookup in a test; nil
// means os.Getenv. porte still reads nothing behind the caller's back. Values
// are trimmed, and a blank one counts as unset.
//
// defaults holds what the environment does not: the fields with no variable
// (ExtraScopes, the TTLs), and the app's own fallback for a variable its
// deployments may leave out, such as a SuccessURL taken from the first CORS
// origin, a MobileRedirect of the app's custom scheme, or SSOOnly true. A
// variable that is set wins over its default. A default MobileRedirect is
// dropped while OIDC_ISSUER is unset, since Validate refuses one without an
// issuer and the deployment set neither.
//
// The result went through Validate, so a half-configured provider is an
// error naming every missing variable, as is an SSO_ONLY that is not a
// boolean. An unset OIDC_ISSUER is not an error: it leaves OIDC off, the
// suite convention. An app that requires single sign-on checks Enabled.
func ConfigFromEnv(get func(string) string, defaults Config) (Config, error) {
	if get == nil {
		get = os.Getenv
	}
	cfg := defaults
	for _, entry := range envFields {
		if value := strings.TrimSpace(get(entry.name)); value != "" {
			*entry.field(&cfg) = value
		}
	}
	if cfg.Issuer == "" && strings.TrimSpace(get("OIDC_MOBILE_REDIRECT")) == "" {
		cfg.MobileRedirect = ""
	}
	if raw := strings.TrimSpace(get("SSO_ONLY")); raw != "" {
		ssoOnly, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("porte: SSO_ONLY must be a boolean, got %q", raw)
		}
		cfg.SSOOnly = ssoOnly
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
