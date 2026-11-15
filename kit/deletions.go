package kit

import (
	"context"
	"errors"
	"log/slog"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/porte/pg"
)

// ErrDeletionsIncomplete is what NewDeletions returns when single sign-on is
// configured and the store or the callback is missing.
var ErrDeletionsIncomplete = errors.New("porte/kit: NewDeletions needs a Store and an OnPersonDeleted callback")

// DeletionsConfig is what NewDeletions wires into porte/directory's receiver
// of Registre's account erasures.
type DeletionsConfig struct {
	// OIDC is the app's sign-in configuration. Its Issuer, ClientID and
	// ClientSecret are the credentials the receiver polls Registre with and
	// verifies its signed push against.
	OIDC porte.Config

	// Store erases porte's own rows for the identity after the callback,
	// and tells the receiver when an erased subject holds an account again.
	Store *pg.Store

	// OnPersonDeleted erases the app's data for the person; it is the only
	// part an app writes. (*Store).EraseAccount fits as it is, and an app
	// with files to remove wraps it. It must be idempotent: the receiver
	// delivers at least once.
	OnPersonDeleted func(ctx context.Context, provider, subject string) error

	// State persists the receiver's cursor. Nil means Store.DeletionState(),
	// the directory_deletion_state table.
	State directory.StateStore

	Logger *slog.Logger
}

// NewDeletions builds the receiver the way every suite app wires it: Registre
// is polled and its push verified with the sign-in credentials, the callback
// runs first, then pg.Store.EraseIdentity, and pg.Store.HoldsIdentity erases
// again a handled subject whose account came back.
//
// It changes nothing about the receiver itself: verification, idempotency and
// the 202, 400, 500 and 503 answers stay in porte/directory. The app still
// mounts Handler on directory.DeletionsPath, outside its session and CSRF
// middleware, and starts Run in one replica.
//
// It returns nil and no error when cfg.OIDC has no issuer, since there is no
// Registre to ask. Pass that nil through ErasedGuard, never straight into
// oidc.Deps.Erased.
func NewDeletions(cfg DeletionsConfig) (*directory.Deletions, error) {
	if !cfg.OIDC.Enabled() {
		return nil, nil
	}
	if cfg.Store == nil || cfg.OnPersonDeleted == nil {
		return nil, ErrDeletionsIncomplete
	}
	state := cfg.State
	if state == nil {
		state = cfg.Store.DeletionState()
	}
	return &directory.Deletions{
		Client: directory.Client{
			Issuer:       cfg.OIDC.Issuer,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
		},
		OnPersonDeleted: cfg.OnPersonDeleted,
		Erase:           cfg.Store.EraseIdentity,
		Holds:           cfg.Store.HoldsIdentity,
		State:           state,
		Logger:          cfg.Logger,
	}, nil
}

// ErasedGuard returns deletions as the ledger oidc.Deps.Erased asks before it
// gives an identity an account, or nil when there is no receiver. A nil
// *directory.Deletions stored in the interface directly would be a non-nil
// porte.ErasedSubjects, and the first sign-in would panic on it.
func ErasedGuard(deletions *directory.Deletions) porte.ErasedSubjects {
	if deletions == nil {
		return nil
	}
	return deletions
}
