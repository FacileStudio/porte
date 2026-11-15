package oidc

import (
	"context"
	stderrors "errors"
	"log/slog"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"
	"github.com/FacileStudio/tronc/errors"

	"golang.org/x/oauth2"
)

// roleRefreshBudget bounds one role refresh. The refresh runs on a context
// the request cannot cancel: once the provider has rotated the refresh token,
// the new one must reach the store, or the next refresh is refused.
const roleRefreshBudget = 30 * time.Second

// errNoGrant is a role refresh with no refresh token to spend. Nothing can
// confirm the cached roles again, so it counts as a refusal.
var errNoGrant = errors.Failed("no refresh token")

// Kit implements session.ClaimsSource: the manager owns the credential, and
// this is the one thing about an identity that only a federated provider can
// answer for.
var _ session.ClaimsSource = (*Kit)(nil)

// Attach fills Roles from the stored identity and refreshes them when
// they have gone stale. It does not fill Email or Name: no store porte reads
// on this path holds either, and going to the app's user table for them would
// double the cost of every authenticated request to serve the handlers that
// do not need them.
//
// It costs a query per request, so it runs only when claims are configured.
// An app that never sets OIDC_CLAIMS_SCOPE pays exactly one query per
// authenticated request, the session lookup.
//
// A refresh the provider refuses fails closed. When the grant is gone
// (invalid_grant after a revoked grant or a disabled account, or no refresh
// token left to spend), the cached roles are dropped from the identity and
// from the row, and the person holds no role until they sign in again. When
// the provider cannot be reached or answers something unusable, the cached
// roles stay and the attempt is stamped, so the next try comes one ClaimsTTL
// later and an outage does not turn every request into a token call.
func (k *Kit) Attach(ctx context.Context, identity *porte.Identity) {
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
	refreshed, err := k.refreshRolesOnce(ctx, stored)
	switch {
	case err == nil:
	case grantGone(err):
		k.logger.Warn("porte: role refresh refused, dropping the cached roles",
			slog.Int64("user_id", identity.UserID), slog.Any("error", err))
		refreshed = k.dropRoles(ctx, stored)
	default:
		k.keepRoles(ctx, stored, err)
		return
	}
	identity.Roles = refreshed.Roles
	identity.RolesSyncedAt = refreshed.RolesSyncedAt
}

// keepRoles records a refresh attempt that failed without a refusal, so the
// cached roles stand and the next attempt waits one ClaimsTTL.
func (k *Kit) keepRoles(ctx context.Context, stored porte.StoredIdentity, cause error) {
	k.logger.Warn("porte: role refresh failed, keeping the cached claim",
		slog.Int64("user_id", stored.UserID), slog.Any("error", cause))
	if err := k.deps.Identities.MarkRolesSynced(ctx, stored.Provider, stored.Subject, k.now()); err != nil {
		k.logger.Warn("porte: failed to record the refresh attempt", slog.Any("error", err))
	}
}

// grantGone reports a refresh the provider will never accept again: the
// token endpoint said invalid_grant, or there is no refresh token.
func grantGone(err error) bool {
	var refused *oauth2.RetrieveError
	return stderrors.Is(err, errNoGrant) || (stderrors.As(err, &refused) && refused.ErrorCode == "invalid_grant")
}

// dropRoles handles a refused grant. It reads the row again first: when it
// now holds another refresh token, a second replica or a new sign-in replaced
// the one just refused, and that row is the current answer. Otherwise the
// roles are cleared and saved, so they stay gone until the next sign-in. A
// row that cannot be read, or saved, still yields no roles for this request.
func (k *Kit) dropRoles(ctx context.Context, stored porte.StoredIdentity) porte.StoredIdentity {
	latest, ok, err := k.identityFor(ctx, stored.UserID)
	if err != nil || !ok {
		stored.Roles = nil
		return stored
	}
	if latest.Tokens.RefreshToken != "" && latest.Tokens.RefreshToken != stored.Tokens.RefreshToken {
		return latest
	}
	latest.Roles = nil
	latest.RolesSyncedAt = k.now()
	if err := k.deps.Identities.Save(ctx, latest); err != nil {
		k.logger.Warn("porte: failed to record the dropped roles", slog.Int64("user_id", stored.UserID), slog.Any("error", err))
	}
	return latest
}

// refreshRolesOnce runs one refresh per identity at a time and shares its
// outcome with the requests that arrived meanwhile.
func (k *Kit) refreshRolesOnce(ctx context.Context, stored porte.StoredIdentity) (porte.StoredIdentity, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), roleRefreshBudget)
	defer cancel()
	result, err, _ := k.roleRefreshes.Do(stored.Provider+"\x00"+stored.Subject, func() (any, error) {
		return k.refreshRoles(ctx, stored)
	})
	refreshed, ok := result.(porte.StoredIdentity)
	if !ok {
		return stored, errors.Failed("the role refresh returned no identity")
	}
	return refreshed, err
}

// refreshRoles trades the refresh token for a new ID token and reads the roles
// claim off it. This is what offline_access, already requested by every app,
// was for. It always spends the refresh token, even while the stored access
// token is still valid: a still-valid access token says nothing about the
// roles, and only a refresh response carries an ID token.
//
// The rotated tokens are saved whatever the ID token turns out to be, since
// the old refresh token is spent. An ID token with no roles claim means the
// person holds no role any more: Registre leaves the claim out when the last
// role is revoked.
func (k *Kit) refreshRoles(ctx context.Context, stored porte.StoredIdentity) (porte.StoredIdentity, error) {
	if stored.Tokens.RefreshToken == "" {
		return stored, errNoGrant
	}
	token, err := k.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: stored.Tokens.RefreshToken}).Token()
	if err != nil {
		return stored, err
	}
	stored.Tokens = toTokenSet(token)
	roles, rolesErr := k.refreshedRoles(ctx, token)
	if rolesErr == nil {
		stored.Roles = roles
		stored.RolesSyncedAt = k.now()
	}
	if err := k.deps.Identities.Save(ctx, stored); err != nil {
		return stored, err
	}
	return stored, rolesErr
}

// refreshedRoles verifies the ID token of a refresh response and returns its
// roles claim, empty when the claim is absent.
func (k *Kit) refreshedRoles(ctx context.Context, token *oauth2.Token) ([]string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Failed("the refresh response carried no id_token")
	}
	idToken, err := k.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	var claim struct {
		Roles []string `json:"roles"`
	}
	if err := idToken.Claims(&claim); err != nil {
		return nil, err
	}
	if claim.Roles == nil {
		return []string{}, nil
	}
	return claim.Roles, nil
}
