package pg

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
)

// EraseIdentity removes what porte holds for one erased identity: the
// identity row with its provider tokens, and every session, named token,
// login code and magic link of the account it belonged to. It leaves
// porte_users alone, because the app's own tables may point at it; the app
// removes the account in its OnPersonDeleted callback, which runs first.
//
// An identity that is already gone is not an error, so a retry after a
// failure further along is safe. The account's exclusive advisory lock orders
// it against a bound insert, as a purge is ordered.
func (s *Store) EraseIdentity(ctx context.Context, provider, subject string) error {
	var userID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM porte_identities WHERE provider = $1 AND subject = $2`, provider, subject).Scan(&userID)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("porte/pg: find identity to erase: %w", err)
	}
	return withUserLock(ctx, s.db, userID, false, func(q querier) error {
		for _, table := range []string{"porte_sessions", "porte_login_codes", "porte_magic_links"} {
			if _, err := q.ExecContext(ctx, "DELETE FROM "+table+" WHERE user_id = $1", userID); err != nil {
				return fmt.Errorf("porte/pg: erase %s: %w", table, err)
			}
		}
		_, err := q.ExecContext(ctx, `DELETE FROM porte_identities WHERE provider = $1 AND subject = $2`, provider, subject)
		if err != nil {
			return fmt.Errorf("porte/pg: erase identity: %w", err)
		}
		return nil
	})
}
