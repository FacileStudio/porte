// Package devicelogin is the default half of porte's CLI login: the OAuth 2.0
// device grant (RFC 8628) against the suite's identity provider, then a trade
// of the provider's token for the app's own session at porte's device
// exchange. Nothing listens on a port and nothing is typed or pasted, so it
// works over SSH, in a container and on a server whose browser is somewhere
// else, which is where porte/loopback fails.
//
// Login runs the whole flow. A CLI that wants its own output calls the steps
// instead: Mounted, Discover, Authorize, Poll, Exchange. When the app has not
// shipped the exchange, Login returns ErrExchangeNotMounted before printing
// anything, and the CLI falls back to porte/loopback.
//
// Like loopback, it holds no credentials and writes no files: the session it
// returns is the CLI's to store, and the provider's token is discarded once it
// has been traded.
//
// Standard library only, on purpose, apart from porte's own stdlib-only
// packages. Every CLI in the suite links this, and a binary that polls a token
// endpoint must not compile go-oidc, oauth2, chi, pgx or tronc to do it.
package devicelogin

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/FacileStudio/porte/loopback"
)

// GrantType is RFC 8628 §3.4's grant identifier, spelled exactly as the RFC
// spells it.
const GrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DefaultIssuer is Registre, the suite's provider. Only its root discovery
// document is real.
const DefaultIssuer = "https://sso.facile.studio"

// DefaultClientID is the public client Registre registers for every suite CLI.
// It has no secret, because a secret compiled into a binary is not one.
const DefaultClientID = "facile-cli"

// DefaultScope is what the app needs to name the account behind the token.
// offline_access is not asked for: a refresh token is one more credential to
// store, and the app session is the one that has to last.
const DefaultScope = "openid email profile"

// Options configures Login. Only AppOrigin is required.
type Options struct {
	// AppOrigin is the app's origin, such as https://journal.facile.studio.
	AppOrigin string
	// Mount is the path the app serves porte under: "/api" for every suite
	// app, "" for an app serving its API from the root.
	Mount string
	// Issuer defaults to DefaultIssuer. Prefer the issuer the app advertises
	// when the CLI already reads one.
	Issuer string
	// ClientID defaults to DefaultClientID.
	ClientID string
	// Scope defaults to DefaultScope.
	Scope string
	// Out receives the one line naming the approval link. Nil is os.Stderr,
	// so a CLI whose stdout is piped still shows it.
	Out io.Writer
	// OpenBrowser is tried once with the link, and its result is ignored.
	// Nil is loopback.OpenBrowser; a CLI with --no-browser passes a function
	// that returns false.
	OpenBrowser func(string) bool
}

// Login runs the device grant end to end and returns the app's session. It
// probes the exchange first, so ErrExchangeNotMounted arrives before anything
// is printed. It then prints one line with the approval link, tries the
// browser, polls until the user approves, and trades the token.
func Login(ctx context.Context, opts Options) (Session, error) {
	opts = opts.withDefaults()
	mounted, err := Mounted(ctx, opts.AppOrigin, opts.Mount)
	if err != nil {
		return Session{}, err
	}
	if !mounted {
		return Session{}, ErrExchangeNotMounted
	}
	endpoints, err := Discover(ctx, opts.Issuer)
	if err != nil {
		return Session{}, err
	}
	auth, err := endpoints.Authorize(ctx, opts.ClientID, opts.Scope)
	if err != nil {
		return Session{}, err
	}
	opts.announce(auth)
	accessToken, err := endpoints.Poll(ctx, opts.ClientID, auth)
	if err != nil {
		return Session{}, err
	}
	return Exchange(ctx, opts.AppOrigin, opts.Mount, accessToken)
}

// withDefaults fills every optional field left empty.
func (o Options) withDefaults() Options {
	if o.Issuer == "" {
		o.Issuer = DefaultIssuer
	}
	if o.ClientID == "" {
		o.ClientID = DefaultClientID
	}
	if o.Scope == "" {
		o.Scope = DefaultScope
	}
	if o.Out == nil {
		o.Out = os.Stderr
	}
	if o.OpenBrowser == nil {
		o.OpenBrowser = loopback.OpenBrowser
	}
	return o
}

// announce prints the one line the user acts on and tries the browser. The
// user code is a confirmation hint, never something to type, unless the
// provider sent no complete link and the bare page will ask for it.
func (o Options) announce(auth Authorization) {
	if auth.VerificationURIComplete != "" {
		_, _ = fmt.Fprintf(o.Out, "Approve this sign-in at %s (code %s)\n", auth.Link(), auth.UserCode)
	} else {
		_, _ = fmt.Fprintf(o.Out, "Approve this sign-in at %s and enter the code %s\n", auth.Link(), auth.UserCode)
	}
	o.OpenBrowser(auth.Link())
}
