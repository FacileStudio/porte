package pg

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"log/slog"
	"os"
)

// TokenKeyEnv names the variable holding the secrets [ParseTokenSealer]
// reads, the name every suite app sets.
const TokenKeyEnv = "PORTE_TOKEN_KEY"

// NewFromEnv returns a store over db that seals the provider's tokens under
// the key in PORTE_TOKEN_KEY. An unset or blank variable leaves sealing off,
// as [New] without a sealer does. A value that is set but unreadable is an
// error, so a mistyped key stops the boot and never silently stores tokens
// in the clear.
//
// It is the newPorteStore every suite app carried in porte_seal.go.
func NewFromEnv(db *sql.DB) (*Store, error) {
	sealer, err := ParseTokenSealer(os.Getenv(TokenKeyEnv))
	if err != nil {
		return nil, fmt.Errorf("%s is set but invalid: %w", TokenKeyEnv, err)
	}
	return New(db, WithTokenSealer(sealer)), nil
}

// ResealInBackground runs [IdentityStore.ResealIdentities] once in its own
// goroutine and logs the outcome, so the rows written before the key was set,
// or under an older key, are sealed without anyone signing in again. It
// returns at once, and does nothing for a store without a sealer. A nil
// logger means [slog.Default]. Cancel ctx to stop the pass at shutdown.
//
// It is the resealInBackground every suite app carried in porte_seal.go.
func ResealInBackground(ctx context.Context, store *Store, logger *slog.Logger) {
	if store == nil || store.sealer == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	go func() {
		count, err := store.Identities().ResealIdentities(ctx)
		if err != nil && !stderrors.Is(err, context.Canceled) {
			logger.Warn("porte token reseal failed", slog.Int("resealed", count), slog.Any("error", err))
			return
		}
		logger.Info("porte token reseal complete", slog.Int("resealed", count))
	}()
}
