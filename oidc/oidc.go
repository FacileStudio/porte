// Package oidc is porte's engine: the OIDC flow, the seven routes and the
// session middleware.
//
// It is separate from the contract package on purpose. An app's stores and
// domain code import porte and compile against plain types; only main.go
// imports this package and inherits go-oidc, oauth2 and chi with it.
//
// Wiring is one call:
//
//	kit, err := oidc.New(ctx, cfg, oidc.Deps{Users: store, Identities: store, Sessions: store, Codes: store})
//	kit.Mount(router)
//	router.Group(func(r chi.Router) { r.Use(kit.RequireAuth); ... })
package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/FacileStudio/porte"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Deps are the stores the kit writes through. Users, Identities and Sessions
// are required whenever OIDC is enabled; Codes is required for the CLI flow
// and Avatars is optional.
//
// porte/pg implements all four over the default identity tables, so an app
// that has no reason to be exotic passes the same value four times.
type Deps struct {
	Users      porte.UserStore
	Identities porte.IdentityStore
	Sessions   porte.SessionStore
	Codes      porte.LoginCodeStore
	Avatars    porte.AvatarStore
	Logger     *slog.Logger
}

// Kit serves porte's routes and authenticates requests.
type Kit struct {
	cfg      porte.Config
	deps     Deps
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth    oauth2.Config
	logger   *slog.Logger
	now      func() time.Time
}

// New performs discovery and returns a kit. It is the boot path, so every
// misconfiguration it can detect is detected here: a half-filled environment,
// an unreachable issuer, and a roles scope the provider does not offer.
//
// A disabled config (no OIDC_ISSUER) is not an error. New returns a kit that
// serves only RouteConfig and authenticates sessions, which is what an app
// running without SSO needs and what every app does today.
func New(ctx context.Context, cfg porte.Config, deps Deps) (*Kit, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	kit := &Kit{cfg: cfg.Resolved(), deps: deps, logger: logger, now: time.Now}

	if !cfg.Enabled() {
		if deps.Sessions == nil {
			return nil, fmt.Errorf("porte/oidc: a SessionStore is required even with OIDC disabled")
		}
		return kit, nil
	}

	for name, missing := range map[string]bool{
		"UserStore":      deps.Users == nil,
		"IdentityStore":  deps.Identities == nil,
		"SessionStore":   deps.Sessions == nil,
		"LoginCodeStore": deps.Codes == nil,
	} {
		if missing {
			return nil, fmt.Errorf("porte/oidc: OIDC is enabled but Deps.%s is nil", name)
		}
	}

	provider, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("porte/oidc: discovery failed for %s: %w", cfg.Issuer, err)
	}
	kit.provider = provider
	kit.verifier = provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	kit.oauth = oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes(),
	}

	if err := kit.guardClaimsScope(); err != nil {
		return nil, err
	}
	return kit, nil
}

// guardClaimsScope refuses to boot when the roles scope is configured but the
// provider does not advertise it.
//
// authentik's own documentation carries the trap: group-based authorization
// needs the scope attached to the provider's property mappings *and* requested
// by the client, and when either half is missing the claim simply never
// arrives — every rule denies, silently, with no error anywhere. A silent deny
// in the auth path is the worst failure mode available, so half of it is
// caught here and the other half on the first callback, where the claim's
// absence is observable.
func (k *Kit) guardClaimsScope() error {
	if !k.cfg.ClaimsEnabled() {
		return nil
	}
	var discovery struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := k.provider.Claims(&discovery); err != nil {
		return fmt.Errorf("porte/oidc: cannot read the discovery document: %w", err)
	}
	if len(discovery.ScopesSupported) == 0 {
		k.logger.Warn("porte: provider advertises no scopes_supported, cannot verify the roles scope",
			slog.String("scope", k.cfg.ClaimsScope))
		return nil
	}
	for _, scope := range discovery.ScopesSupported {
		if scope == k.cfg.ClaimsScope {
			return nil
		}
	}
	return fmt.Errorf(
		"porte/oidc: the roles scope %q is not offered by %s — attach the scope mapping to the provider's property mappings, or unset it here; leaving it half-configured makes every role check deny silently",
		k.cfg.ClaimsScope, k.cfg.Issuer)
}

// Config reports the resolved configuration, mostly so an app can read the
// TTLs it did not set.
func (k *Kit) Config() porte.Config { return k.cfg }

// Enabled reports whether the OIDC routes are live.
func (k *Kit) Enabled() bool { return k.provider != nil }

// tokenSource returns a source that refreshes the stored tokens as needed.
func (k *Kit) tokenSource(ctx context.Context, tokens porte.TokenSet) oauth2.TokenSource {
	return k.oauth.TokenSource(ctx, &oauth2.Token{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       tokens.Expiry,
	})
}

func toTokenSet(token *oauth2.Token) porte.TokenSet {
	return porte.TokenSet{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}
}

// claimsFromIDToken normalises a verified ID token into the one type an app's
// UserStore has to understand.
func (k *Kit) claimsFromIDToken(idToken *gooidc.IDToken) (porte.Claims, error) {
	var raw struct {
		Email             string `json:"email"`
		EmailVerified     any    `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		Picture           string `json:"picture"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return porte.Claims{}, fmt.Errorf("porte/oidc: cannot parse ID token claims: %w", err)
	}

	var roles []string
	if k.cfg.ClaimsEnabled() {
		var rolesOnly struct {
			Roles []string `json:"roles"`
		}
		if err := idToken.Claims(&rolesOnly); err != nil {
			return porte.Claims{}, fmt.Errorf("porte/oidc: cannot parse the roles claim: %w", err)
		}
		if rolesOnly.Roles == nil {
			// The other half of the startup guard. The scope was granted,
			// so the mapping is what is missing, and the app would
			// otherwise deny every role check without a single error.
			return porte.Claims{}, fmt.Errorf(
				"porte/oidc: scope %q was granted but no roles claim arrived — the provider is missing its scope mapping",
				k.cfg.ClaimsScope)
		}
		roles = rolesOnly.Roles
	}

	return porte.Claims{
		Provider:          k.cfg.Issuer,
		Subject:           idToken.Subject,
		Email:             raw.Email,
		EmailVerified:     emailClaimTrusted(raw.EmailVerified),
		Name:              raw.Name,
		PreferredUsername: raw.PreferredUsername,
		GivenName:         raw.GivenName,
		FamilyName:        raw.FamilyName,
		Picture:           raw.Picture,
		Roles:             roles,
	}, nil
}

// emailClaimTrusted reports whether the email in an ID token may be used to
// match an existing account. Matching on a mutable, unproven email is how an
// identity provider that lets a user set any address becomes an account
// takeover primitive, so the fallback is refused when the provider explicitly
// says the address is unverified. An absent claim is treated as trusted: the
// provider is asserting nothing either way, and refusing it would strand every
// account created before oidc_subject was recorded.
//
// This is Nuage's function, unchanged. All six apps grew a version of it.
func emailClaimTrusted(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case bool:
		return typed
	case string:
		return typed != "false" && typed != "False" && typed != "FALSE"
	default:
		return false
	}
}
