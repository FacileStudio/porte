package devicelogin

import "errors"

// The refusals this package can return, as sentinels in loopback's style: the
// only thing a CLI does with them is choose what to print and which flow to
// try next, so errors.Is is the whole interface.
//
// Cancellation is not among them. Every step returns ctx.Err() unchanged when
// the caller's context ends, so a CLI that already treats Ctrl-C as a quiet
// exit needs nothing new from here.
var (
	// ErrExchangeNotMounted means the app answered 404 on the device exchange
	// route: it has not shipped porte's device exchange, or it runs without
	// OIDC_CLI_AUDIENCE. porte guarantees an app that mounts the route never
	// answers it with 404, so this is the signal to fall back to loopback.
	ErrExchangeNotMounted = errors.New("devicelogin: this app does not serve the device exchange")

	// ErrAccountNotLinked means the app refused the provider's token with 401.
	// The exchange looks the subject up and never creates an account, so the
	// usual cause is an account that has never signed in to this app through
	// the browser. The fix is to do that once and run the login again.
	ErrAccountNotLinked = errors.New("devicelogin: this account has never signed in to the app in a browser")

	// ErrNoDeviceGrant means the provider's discovery document names no
	// device authorization endpoint, or lists its grants without RFC 8628's.
	// Nothing is broken; the CLI should use the loopback flow instead.
	ErrNoDeviceGrant = errors.New("devicelogin: the identity provider does not offer the device grant")

	// ErrDenied means the user refused the sign-in at the provider. It stays
	// distinct from ErrExpired: telling somebody their code expired when they
	// refused it sends them to retry the thing they meant to stop.
	ErrDenied = errors.New("devicelogin: the sign-in was refused at the identity provider")

	// ErrExpired means nobody approved the sign-in before the code expired,
	// whether the provider said expired_token or the wait ran out first. It
	// is the one failure worth offering to retry.
	ErrExpired = errors.New("devicelogin: the sign-in code expired before it was approved")
)
