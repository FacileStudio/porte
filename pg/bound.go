package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/FacileStudio/porte"
)

// querier is what a write needs, from a pool or inside a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// withUserLock runs write in a transaction that first takes the user row's
// lock in mode, so every writer that can race a purge locks in the purge's
// order: the user row, then the identities.
func withUserLock(ctx context.Context, db *sql.DB, userID int64, mode string, write func(querier) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("porte/pg: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM porte_users WHERE id = $1 `+mode, userID); err != nil {
		return fmt.Errorf("porte/pg: lock user: %w", err)
	}
	if err := write(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("porte/pg: commit: %w", err)
	}
	return nil
}

// whileBound runs insert directly when binding names no provider, and
// otherwise only while (Provider, Subject) still belongs to binding.UserID,
// checked under a KEY SHARE lock on the user row. It answers
// porte.ErrNotFound when the identity is gone.
func whileBound(ctx context.Context, db *sql.DB, binding porte.Session, insert func(querier) error) error {
	if binding.Provider == "" {
		return insert(db)
	}
	return withUserLock(ctx, db, binding.UserID, "FOR KEY SHARE", func(q querier) error {
		var exists bool
		if err := q.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM porte_identities WHERE provider = $1 AND subject = $2 AND user_id = $3)`,
			binding.Provider, binding.Subject, binding.UserID).Scan(&exists); err != nil {
			return fmt.Errorf("porte/pg: check the identity: %w", err)
		}
		if !exists {
			return porte.ErrNotFound
		}
		return insert(q)
	})
}
