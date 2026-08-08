package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/tronc/errors"
	"github.com/FacileStudio/tronc/httpjson"
)

// touchInterval coalesces last_used_at writes. Recording the exact second of
// every request would put one UPDATE on the hot path of every authenticated
// call to buy nothing: the column exists so a user can recognise a session in
// a list, and a minute of resolution does that.
const touchInterval = time.Minute

// RequireAuth rejects unauthenticated requests. On success the handler reads
// the caller with porte.From(r.Context()).
func (k *Kit) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := k.authenticate(w, r)
		if err != nil {
			httpjson.WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(porte.WithIdentity(r.Context(), identity)))
	})
}

// Optional attaches an identity when the request carries a valid one and lets
// the request through either way. It is for routes that serve both a signed-in
// and an anonymous caller — a public share link that shows an edit button to
// its owner.
func (k *Kit) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := k.authenticate(w, r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(porte.WithIdentity(r.Context(), identity)))
	})
}

// authenticate resolves the credential on a request.
//
// Two transports, and only two: the session cookie and an Authorization
// bearer. No query parameter is read — a credential in a URL lands in access
// logs, referrers and browser history, and the two places that genuinely
// needed one, EventSource and download navigations, are exactly what the
// cookie transport serves for free.
func (k *Kit) authenticate(w http.ResponseWriter, r *http.Request) (porte.Identity, error) {
	token, fromCookie := credential(r)
	if token == "" {
		return porte.Identity{}, errors.Unauthorized("missing auth")
	}

	// A cookie is attached by the browser whether or not the page meant to
	// send it, which is the whole CSRF problem. SameSite=Lax handles the
	// cross-site form post; this handles the rest, because a browser will
	// not attach a custom header cross-site without a preflight the app
	// never answers. Bearer callers are exempt: nothing attaches a header
	// on their behalf.
	if fromCookie && mutating(r) && r.Header.Get(porte.CSRFHeaderName) == "" {
		return porte.Identity{}, errors.Forbidden("missing " + porte.CSRFHeaderName + " header")
	}

	hash := porte.HashToken(token)
	session, err := k.deps.Sessions.Find(r.Context(), hash)
	if err != nil {
		if isErr(err, porte.ErrNotFound) {
			if fromCookie {
				k.clearCookie(w, r, porte.SessionCookieName)
			}
			return porte.Identity{}, errors.Unauthorized("invalid session")
		}
		return porte.Identity{}, errors.Internal("failed to read the session", err)
	}

	now := k.now()
	if session.Expired(now) || k.idledOut(session, now) {
		if fromCookie {
			k.clearCookie(w, r, porte.SessionCookieName)
		}
		// The row is dead either way, and leaving it costs a lookup on
		// every replay of a token that will never authenticate again.
		if err := k.deps.Sessions.Delete(r.Context(), hash); err != nil && !isErr(err, porte.ErrNotFound) {
			k.logger.Warn("porte: failed to drop a dead session", slog.Any("error", err))
		}
		return porte.Identity{}, errors.Unauthorized("session expired")
	}
	if now.Sub(session.LastUsedAt) >= touchInterval {
		if err := k.deps.Sessions.Touch(r.Context(), hash, now); err != nil {
			k.logger.Warn("porte: failed to record session use", slog.Any("error", err))
		}
	}

	identity := porte.Identity{
		UserID:    session.UserID,
		SessionID: session.ID,
	}
	k.attachClaims(r.Context(), &identity)
	return identity, nil
}

// credential returns the token and whether it came from the cookie. Cookie
// first: a browser that has both is a browser, and the cookie is the transport
// with the CSRF check behind it.
func credential(r *http.Request) (token string, fromCookie bool) {
	if value, ok := readCookie(r, porte.SessionCookieName); ok {
		return value, true
	}
	authorization := r.Header.Get("Authorization")
	if len(authorization) > 7 && strings.EqualFold(authorization[:7], "bearer ") {
		return strings.TrimSpace(authorization[7:]), false
	}
	return "", false
}

// idledOut reports whether a session has gone unused for longer than the
// configured idle window. It reads LastUsedAt, which the touch above keeps to
// within a minute — coarse enough to be cheap, far finer than a window
// measured in days.
//
// Labelled sessions are exempt: a named API token driving a nightly job is
// idle by design, and expiring it would break the one credential nobody is
// present to renew.
func (k *Kit) idledOut(session porte.Session, now time.Time) bool {
	idle := k.cfg.IdleTimeout()
	if idle <= 0 || session.IsAPIToken() || session.LastUsedAt.IsZero() {
		return false
	}
	return now.Sub(session.LastUsedAt) >= idle
}

func mutating(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// attachClaims fills Email, Name and Roles from the stored identity, and
// refreshes the roles when they have gone stale.
//
// It costs a query per request, so it runs only when claims are configured —
// which no app does today. An app that never sets OIDC_CLAIMS_SCOPE pays
// exactly one query per authenticated request, the session lookup, which is
// what it pays now.
func (k *Kit) attachClaims(ctx context.Context, identity *porte.Identity) {
	if !k.cfg.ClaimsEnabled() {
		return
	}
	stored, ok, err := k.identityFor(ctx, identity.UserID)
	if err != nil || !ok {
		if err != nil {
			k.logger.Warn("porte: failed to load claims", slog.Int64("user_id", identity.UserID), slog.Any("error", err))
		}
		return
	}

	identity.Roles = stored.Roles
	identity.RolesSyncedAt = stored.RolesSyncedAt

	if !stored.RolesStale(k.now(), k.cfg.ClaimsTTL) {
		return
	}
	refreshed, err := k.refreshRoles(ctx, stored)
	if err != nil {
		// Keeping the stale roles is the right failure: an IdP blip
		// must not silently strip everyone's permissions. The stamp is
		// still moved so a dead refresh token is not retried on every
		// single request — through the narrow write, because `stored`
		// is a pre-refresh read and saving it whole would roll back a
		// token another request may have rotated in the meantime.
		k.logger.Warn("porte: role refresh failed, keeping the cached claim",
			slog.Int64("user_id", identity.UserID), slog.Any("error", err))
		if err := k.deps.Identities.MarkRolesSynced(ctx, stored.Provider, stored.Subject, k.now()); err != nil {
			k.logger.Warn("porte: failed to record the refresh attempt", slog.Any("error", err))
		}
		return
	}
	identity.Roles = refreshed.Roles
	identity.RolesSyncedAt = refreshed.RolesSyncedAt
}

// refreshRoles trades the refresh token for a new ID token and reads the roles
// claim off it. This is what offline_access — already requested by every app —
// was for.
func (k *Kit) refreshRoles(ctx context.Context, stored porte.StoredIdentity) (porte.StoredIdentity, error) {
	if stored.Tokens.RefreshToken == "" {
		return stored, errors.Failed("no refresh token")
	}
	source := k.tokenSource(ctx, stored.Tokens)
	token, err := source.Token()
	if err != nil {
		return stored, err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return stored, errors.Failed("the refresh response carried no id_token")
	}
	idToken, err := k.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return stored, err
	}
	claims, err := k.claimsFromIDToken(idToken)
	if err != nil {
		return stored, err
	}

	stored.Tokens = toTokenSet(token)
	stored.Roles = claims.Roles
	stored.RolesSyncedAt = k.now()
	if err := k.deps.Identities.Save(ctx, stored); err != nil {
		return stored, err
	}
	return stored, nil
}
