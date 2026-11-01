package magiclink

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/tronc/errors"
)

type target struct {
	email  string
	userID int64
	found  bool
}

// Request issues a link to the account behind email and mails it.
//
// It returns nil for an address with no eligible account, for a malformed
// address, and for a caller over a rate limit. An error that told those apart
// from success would turn the form into an account enumeration oracle, and a
// rate limit that only known addresses could trip would be the same oracle.
// Over a limit it still hashes a token and counts, so the refusal costs what
// an issue costs.
//
// The work an unknown address does is the work a known one does, minus the
// write and the mail: a token is generated and hashed, and the store is asked
// the same two counts. The mail is sent after Request returns, because
// delivery is the one step whose duration would give the address away. What
// remains is one insert, and that gap is not hidden.
//
// ip is the source address, empty when unknown. Behind a proxy it is the
// caller's to resolve.
func (k *Kit) Request(ctx context.Context, email, ip string) error {
	who, err := k.lookup(ctx, email)
	if err != nil {
		return err
	}
	now := k.now()
	allowed, err := k.withinLimits(ctx, who, ip, now)
	if err != nil {
		return err
	}
	token, err := porte.NewToken()
	if err != nil {
		return errors.Internal("failed to generate the link", err)
	}
	hash := porte.HashToken(token)
	if !who.found {
		return nil
	}
	if !allowed {
		k.logger.Warn("magic link request over the rate limit", "user_id", who.userID)
		return nil
	}
	return k.issue(ctx, who, porte.MagicLink{
		TokenHash: hash,
		UserID:    who.userID,
		CreatedAt: now,
		ExpiresAt: now.Add(k.cfg.TTL),
		IP:        ip,
	}, token)
}

func (k *Kit) issue(ctx context.Context, who target, link porte.MagicLink, token string) error {
	if err := k.deps.Links.Create(ctx, link); err != nil {
		return errors.Internal("failed to store the link", err)
	}
	k.deliver(ctx, who, token)
	return nil
}

func (k *Kit) lookup(ctx context.Context, email string) (target, error) {
	address, ok := normalizeEmail(email)
	if !ok {
		return target{}, nil
	}
	userID, err := k.deps.FindUser(ctx, address)
	switch {
	case err == nil:
		return target{email: address, userID: userID, found: true}, nil
	case stderrors.Is(err, porte.ErrNotFound):
		return target{}, nil
	default:
		return target{}, errors.Internal("failed to look up the account", err)
	}
}

func (k *Kit) withinLimits(ctx context.Context, who target, ip string, now time.Time) (bool, error) {
	since := now.Add(-porte.MagicLinkRateWindow)
	byUser, err := k.deps.Links.CountSince(ctx, porte.LinkKey{UserID: who.userID}, since)
	if err != nil {
		return false, errors.Internal("failed to count the links", err)
	}
	byIP, err := k.deps.Links.CountSince(ctx, porte.LinkKey{IP: ip}, since)
	if err != nil {
		return false, errors.Internal("failed to count the links", err)
	}
	return byUser < k.cfg.MaxPerEmail && byIP < k.cfg.MaxPerIP, nil
}

func (k *Kit) deliver(ctx context.Context, who target, token string) {
	link := k.deps.BuildLink(token)
	detached := context.WithoutCancel(ctx)
	k.sends.Go(func() {
		sendCtx, cancel := context.WithTimeout(detached, sendTimeout)
		defer cancel()
		if err := k.deps.Send(sendCtx, who.email, link); err != nil {
			k.logger.Error("magic link email failed", "user_id", who.userID, "error", err)
		}
	})
}
