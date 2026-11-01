// Package magiclink is the passwordless half of porte: an email with a
// one-time link, and a consume that lands in the same session as every other
// porte login.
//
// It exists for the user who should not have a password at all, an end
// customer who signs in twice a year. Sharing the flow is worth less than
// sharing its details, and the details are what drift: that the token is only
// ever stored hashed, that spending it is one conditional update, that an
// unknown address and a known one get the same answer, that every way a link
// can be dead returns the same error.
//
// Eligibility is the app's call. The kit asks [Deps.FindUser] for the user
// behind an address and sends nothing when the app says there is none, so
// "only active customers, never staff" is a line in the app's lookup and not a
// flag the package has to know the meaning of.
//
// Consume is POST only, and the package mounts no GET. Mail scanners prefetch
// every link in a message, and a GET that signed in would be spent before the
// human clicked. The app's link points at a page of its own that shows a
// button and posts the token here.
//
// It depends on porte/session, not on porte/oidc, for the same reason
// porte/local does: an app that wants only magic links must not compile an
// OIDC client.
package magiclink

import (
	"context"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"
	"github.com/FacileStudio/tronc/errors"
)

// The request caps per [porte.MagicLinkRateWindow]: five links per account and
// twenty per source address.
const (
	DefaultMaxPerEmail = 5
	DefaultMaxPerIP    = 20
)

// sendTimeout bounds a mail the request has already moved on from.
const sendTimeout = 30 * time.Second

// Config is the link's policy. Zero values take the defaults.
type Config struct {
	// TTL is how long a link stays usable. Defaults to
	// [porte.DefaultMagicLinkTTL].
	TTL time.Duration

	// MaxPerEmail caps the links issued to one account per
	// [porte.MagicLinkRateWindow]. Defaults to DefaultMaxPerEmail.
	MaxPerEmail int

	// MaxPerIP caps the links issued to accounts from one source address per
	// [porte.MagicLinkRateWindow]. Defaults to DefaultMaxPerIP.
	MaxPerIP int

	// ClientIP resolves the source address of a request for the per-source
	// limit and for the stored link. Nil means the host part of RemoteAddr,
	// which is the only address porte trusts by itself.
	//
	// Behind a reverse proxy RemoteAddr is the proxy, every caller shares one
	// bucket, and twenty requests an hour locks everyone out. Set this to
	// read the header your own proxy writes, and only a header a client
	// cannot forge: one that the proxy overwrites rather than appends to.
	// It applies to [Kit.Mount] only; an app calling [Kit.Request] passes the
	// address itself.
	ClientIP func(r *http.Request) string
}

// Deps are the app's half of the flow.
type Deps struct {
	Links    porte.MagicLinkStore
	Sessions *session.Manager
	Logger   *slog.Logger

	// FindUser returns the id of the user an address may receive a link for,
	// or [porte.ErrNotFound]. An account the app does not want signed in this
	// way is not found, and gets the answer a stranger gets.
	FindUser func(ctx context.Context, email string) (int64, error)

	// Send delivers the link. It runs after the response has been written,
	// so a slow mail server cannot tell a caller whether an address exists.
	// The context is not tied to the request.
	Send func(ctx context.Context, email, link string) error

	// BuildLink turns a raw token into the URL put in the email. It should
	// point at a page of the app that posts the token, never at the API.
	BuildLink func(token string) string

	// Allow is checked after the token is spent, and refuses a user who has
	// become ineligible since the link was sent: banned, suspended,
	// deactivated. The link is spent either way.
	//
	// It is required, not optional. A nil default that allowed everyone would
	// let an app forget it and sign in a banned account with a link mailed
	// before the ban. An app with no such state passes a function that
	// always says yes.
	Allow func(ctx context.Context, userID int64) (bool, error)

	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Kit issues links and consumes them.
type Kit struct {
	cfg    Config
	deps   Deps
	logger *slog.Logger
	sends  sync.WaitGroup
}

// New returns a kit. It fails rather than degrading: a link flow missing its
// mailer answers 202 forever and delivers nothing.
func New(cfg Config, deps Deps) (*Kit, error) {
	for name, missing := range map[string]bool{
		"Links":     deps.Links == nil,
		"Sessions":  deps.Sessions == nil,
		"FindUser":  deps.FindUser == nil,
		"Send":      deps.Send == nil,
		"BuildLink": deps.BuildLink == nil,
		"Allow":     deps.Allow == nil,
	} {
		if missing {
			return nil, errors.Failed("porte/magiclink: Deps." + name + " is required")
		}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = porte.DefaultMagicLinkTTL
	}
	if cfg.MaxPerEmail <= 0 {
		cfg.MaxPerEmail = DefaultMaxPerEmail
	}
	if cfg.MaxPerIP <= 0 {
		cfg.MaxPerIP = DefaultMaxPerIP
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Kit{cfg: cfg, deps: deps, logger: logger}, nil
}

// Wait blocks until every email handed to [Deps.Send] has finished, each bounded
// by a 30 second timeout. Call it on shutdown, after the HTTP server has stopped
// accepting requests, so a link is not lost between the response and the mail
// server. Calling it while requests are still arriving races the wait group.
func (k *Kit) Wait() { k.sends.Wait() }

func (k *Kit) now() time.Time {
	if k.deps.Now != nil {
		return k.deps.Now()
	}
	return time.Now()
}

func invalidLink() error {
	return errors.New(errors.Unauthorized("").Code, porte.ErrMagicLinkInvalid.Error(), porte.ErrMagicLinkInvalid)
}

func normalizeEmail(email string) (string, bool) {
	parsed, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return "", false
	}
	return strings.ToLower(parsed.Address), true
}
