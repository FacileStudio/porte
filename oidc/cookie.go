package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/FacileStudio/porte"
)

// flowCookie is the name Nuage, Courrier and the rest already use for the
// state cookie. Keeping it means no third spelling to reconcile later.
const flowCookie = "oidc_state"

// flowTTL bounds how long a login may sit half-finished.
const flowTTL = 10 * time.Minute

// flow is everything the callback needs and the IdP must not see. It rides in
// one HttpOnly cookie rather than three: state, nonce and the PKCE verifier
// have the same lifetime, the same secrecy and the same failure mode, and one
// cookie cannot arrive partially.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	CLI      bool   `json:"c,omitempty"`
	Port     string `json:"p,omitempty"`
}

func (f flow) encode() (string, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeFlow(value string) (flow, bool) {
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return flow{}, false
	}
	var decoded flow
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return flow{}, false
	}
	return decoded, decoded.State != "" && decoded.Verifier != "" && decoded.Nonce != ""
}

// isSecure is Courrier's test, which is the correct one behind Traefik: the
// TLS terminates at the proxy, so r.TLS is nil on every production request and
// deriving the flag from the success URL — as three apps do — marks the cookie
// insecure exactly where it matters.
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	setCookie(w, r, name, "", -1)
}

// setSessionCookie is the whole reason the frontends stop touching tokens:
// HttpOnly puts the credential out of reach of an XSS, and SameSite=Lax with
// the header check on mutating routes covers the CSRF that a cookie invites.
func (k *Kit) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	setCookie(w, r, porte.SessionCookieName, token, int(k.cfg.SessionTTL.Seconds()))
}
