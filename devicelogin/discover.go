package devicelogin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// discoveryPath is the only discovery path worth asking for. Registre answers
// a per-application path with 200 and its dashboard's HTML, a document with no
// endpoints in it and no error to explain why.
const discoveryPath = "/.well-known/openid-configuration"

// Endpoints is the part of a discovery document the grant uses.
type Endpoints struct {
	// DeviceAuthorization is where a sign-in starts, RFC 8628 §3.1.
	DeviceAuthorization string
	// Token is where the CLI polls for the provider's access token.
	Token string
}

// Discover reads the endpoints out of the issuer's root discovery document
// rather than assembling paths, so a provider that moves an endpoint moves it
// for every CLI without a release.
//
// The issuer and both endpoints must be https, or http on loopback for a
// provider on the developer's own machine. Everything the grant trusts comes
// out of this document, so over plaintext anyone on the path chooses the page
// the user is sent to and the endpoint the token is bought from.
//
// A provider that answers but offers no device grant returns ErrNoDeviceGrant.
// Unreachable, unparseable or a non-2xx answer is a plain error, because "could
// not ask" and "was told no" are different answers.
func Discover(ctx context.Context, issuer string) (Endpoints, error) {
	if err := requireSecureURL(issuer); err != nil {
		return Endpoints{}, fmt.Errorf("devicelogin: the issuer is not usable: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+discoveryPath, nil)
	if err != nil {
		return Endpoints{}, err
	}
	status, doc, err := send(request)
	if err != nil {
		return Endpoints{}, err
	}
	if !ok(status) || doc == nil {
		return Endpoints{}, fmt.Errorf("devicelogin: %s served no OpenID configuration (%d)", issuer, status)
	}
	return endpointsFrom(doc)
}

// endpointsFrom checks a discovery document offers the grant and that every
// endpoint it names is one this package may talk to.
//
// grant_types_supported is optional in OpenID Discovery, so only a list that is
// present and lacks the grant counts as a refusal. Registre once advertised the
// endpoint while refusing the grant behind it, which is why the list is read.
func endpointsFrom(doc map[string]any) (Endpoints, error) {
	found := Endpoints{
		DeviceAuthorization: text(doc, "device_authorization_endpoint"),
		Token:               text(doc, "token_endpoint"),
	}
	if found.DeviceAuthorization == "" || found.Token == "" || !listsDeviceGrant(doc) {
		return Endpoints{}, ErrNoDeviceGrant
	}
	for _, endpoint := range []string{found.DeviceAuthorization, found.Token} {
		if err := requireSecureURL(endpoint); err != nil {
			return Endpoints{}, fmt.Errorf("devicelogin: the provider names an unusable endpoint: %w", err)
		}
	}
	return found, nil
}

// listsDeviceGrant reports whether the document's grant list, when it has one,
// carries RFC 8628's grant type.
func listsDeviceGrant(doc map[string]any) bool {
	grants, present := doc["grant_types_supported"].([]any)
	if !present {
		return true
	}
	for _, grant := range grants {
		if named, _ := grant.(string); named == GrantType {
			return true
		}
	}
	return false
}

// requireSecureURL refuses anything the grant should not trust, open, or send a
// token to: a scheme other than http or https, and plaintext http anywhere but
// loopback.
func requireSecureURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("%q is plaintext http, which only loopback may be", raw)
	default:
		return fmt.Errorf("%q is not an http or https URL", raw)
	}
}

// isLoopback reports whether a host names this machine.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
