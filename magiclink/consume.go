package magiclink

import (
	"context"
	stderrors "errors"
	"net/http"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/tronc/errors"
)

// Consume spends a link and signs its user in, setting the session cookie and
// returning the bearer token, so one call serves a browser and a CLI.
//
// Every way a link can be dead returns [porte.ErrMagicLinkInvalid]: unknown,
// expired, spent, superseded, and a user [Deps.Allow] has since refused. The
// token is spent by the time Allow runs, so a refused user cannot retry it.
func (k *Kit) Consume(ctx context.Context, w http.ResponseWriter, r *http.Request, token string) (int64, string, error) {
	if k.federated {
		return 0, "", disabled()
	}
	userID, err := k.deps.Links.Consume(ctx, porte.HashToken(token), k.now())
	if stderrors.Is(err, porte.ErrNotFound) {
		return 0, "", invalidLink()
	}
	if err != nil {
		return 0, "", errors.Internal("failed to consume the link", err)
	}
	if err := k.allowed(ctx, userID); err != nil {
		return 0, "", err
	}
	sessionToken, _, err := k.deps.Sessions.IssueCookie(ctx, w, r, userID)
	if err != nil {
		return 0, "", err
	}
	return userID, sessionToken, nil
}

func (k *Kit) allowed(ctx context.Context, userID int64) error {
	ok, err := k.deps.Allow(ctx, userID)
	if err != nil {
		return errors.Internal("failed to check the account", err)
	}
	if !ok {
		k.logger.Warn("magic link consumed by a user the app refused", "user_id", userID)
		return invalidLink()
	}
	return nil
}
