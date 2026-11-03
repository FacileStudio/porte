package devicelogin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// exchangePath is porte's device exchange route, relative to the app's mount.
// It matches porte.RouteDeviceExchange by hand rather than by import, because
// this package does not import the contract.
const exchangePath = "/auth/oidc/device/exchange"

// Session is what the app hands back for the provider's token: its own bearer
// session, which the CLI stores exactly where it stores a token today.
type Session struct {
	// Token is the app's opaque session token, sent as "Bearer <token>".
	Token string
	// UserID is the app's id for the account, as the app spells it.
	UserID string
}

// Exchange trades the provider's access token for the app's own session at
// POST <appOrigin><mount>/auth/oidc/device/exchange. mount is the path the app
// serves porte under, "/api" for every suite app and "" for the root, as in
// loopback.LoginURL.
//
// A 404 returns ErrExchangeNotMounted and a 401 returns ErrAccountNotLinked.
// The provider's token is never written anywhere; only the session is returned.
func Exchange(ctx context.Context, appOrigin, mount, accessToken string) (Session, error) {
	body, err := json.Marshal(map[string]string{"access_token": accessToken})
	if err != nil {
		return Session{}, err
	}
	status, doc, err := postExchange(ctx, appOrigin, mount, body)
	if err != nil {
		return Session{}, err
	}
	switch {
	case status == http.StatusNotFound:
		return Session{}, ErrExchangeNotMounted
	case status == http.StatusUnauthorized:
		return Session{}, ErrAccountNotLinked
	case !ok(status):
		return Session{}, fmt.Errorf("devicelogin: the app refused the exchange (%d: %s)", status, refusal(doc))
	}
	session := Session{Token: text(doc, "token"), UserID: text(doc, "user_id")}
	if session.Token == "" {
		return Session{}, fmt.Errorf("devicelogin: the app accepted the exchange but sent no session token")
	}
	return session, nil
}

// Mounted reports whether the app serves the device exchange, so a CLI can pick
// the device grant or loopback before printing anything. It posts an empty
// body: porte answers that with 400 when the route is mounted and the router
// answers 404 when it is not, and nothing else is read from the answer.
func Mounted(ctx context.Context, appOrigin, mount string) (bool, error) {
	status, _, err := postExchange(ctx, appOrigin, mount, nil)
	if err != nil {
		return false, err
	}
	return status != http.StatusNotFound, nil
}

// postExchange posts a JSON body to the exchange route. The origin must be
// https or loopback http, because the body carries the provider's token.
func postExchange(ctx context.Context, appOrigin, mount string, body []byte) (int, map[string]any, error) {
	if err := requireSecureURL(appOrigin); err != nil {
		return 0, nil, fmt.Errorf("devicelogin: the app origin is not usable: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL(appOrigin, mount), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return send(request)
}

// exchangeURL joins origin, mount and route the way loopback.LoginURL does, so
// the slashes are the caller's to forget.
func exchangeURL(appOrigin, mount string) string {
	target := strings.TrimRight(appOrigin, "/")
	if at := strings.Trim(mount, "/"); at != "" {
		target += "/" + at
	}
	return target + exchangePath
}
