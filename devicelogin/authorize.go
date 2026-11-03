package devicelogin

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// defaultInterval is the poll cadence when the provider names none, RFC 8628
// §3.2's own default.
const defaultInterval = 5 * time.Second

// defaultExpiry bounds the wait when the provider names no expires_in.
const defaultExpiry = 10 * time.Minute

// Authorization is the device authorization response, RFC 8628 §3.2.
type Authorization struct {
	// DeviceCode is what the CLI polls with. It never leaves this process.
	DeviceCode string
	// UserCode is the code the provider shows on its approval page. With a
	// complete URI the user never types it; it is printed so they can check
	// the page they landed on is the one this terminal started.
	UserCode string
	// VerificationURI is the approval page without the code in it.
	VerificationURI string
	// VerificationURIComplete carries the code in the URL, so following the
	// link is the whole job. It is optional in the RFC; Registre sends it.
	VerificationURIComplete string
	// Interval is the poll cadence the provider asked for.
	Interval time.Duration
	// ExpiresIn is how long the codes stay valid.
	ExpiresIn time.Duration
}

// Link is the address to put in front of the user: the complete URI when the
// provider sent one, the bare page otherwise.
func (a Authorization) Link() string {
	if a.VerificationURIComplete != "" {
		return a.VerificationURIComplete
	}
	return a.VerificationURI
}

// Authorize is RFC 8628 §3.1. It sends no client secret, because a CLI is a
// public client with nowhere to keep one.
//
// The verification URIs are checked before they are returned. They are the one
// part of the flow handed to the operating system rather than to a parser: the
// caller prints them and opens them, so a provider answering with a file: or
// javascript: URL would be choosing what this machine runs.
func (e Endpoints) Authorize(ctx context.Context, clientID, scope string) (Authorization, error) {
	status, doc, err := postForm(ctx, e.DeviceAuthorization, url.Values{
		"client_id": {clientID},
		"scope":     {scope},
	})
	if err != nil {
		return Authorization{}, err
	}
	if !ok(status) {
		return Authorization{}, fmt.Errorf("devicelogin: the provider would not start a sign-in (%d: %s)",
			status, refusal(doc))
	}
	auth := Authorization{
		DeviceCode:              text(doc, "device_code"),
		UserCode:                text(doc, "user_code"),
		VerificationURI:         text(doc, "verification_uri"),
		VerificationURIComplete: text(doc, "verification_uri_complete"),
		Interval:                seconds(doc, "interval", defaultInterval),
		ExpiresIn:               seconds(doc, "expires_in", defaultExpiry),
	}
	if err := usable(auth); err != nil {
		return Authorization{}, err
	}
	return auth, nil
}

// usable refuses an authorization missing a required field, or carrying a
// verification address this CLI should not put in front of a human or hand to
// a browser.
func usable(auth Authorization) error {
	if auth.DeviceCode == "" || auth.UserCode == "" || auth.VerificationURI == "" {
		return fmt.Errorf("devicelogin: the provider's device authorization is missing a field")
	}
	for _, candidate := range []string{auth.VerificationURI, auth.VerificationURIComplete} {
		if candidate == "" {
			continue
		}
		if err := requireSecureURL(candidate); err != nil {
			return fmt.Errorf("devicelogin: the provider's verification address is not usable: %w", err)
		}
	}
	return nil
}
