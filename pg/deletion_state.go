package pg

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"regexp"
)

// DeletionStateTable is the table [DeletionState] reads when Table is empty,
// the name most suite apps already gave it.
const DeletionStateTable = "directory_deletion_state"

// DeletionStateSchema creates [DeletionStateTable] for an app that has none.
// It is not part of [Schema]: the app owns this table and creates it in its
// own migrations, as every suite app does today.
const DeletionStateSchema = `
CREATE TABLE IF NOT EXISTS directory_deletion_state (
	id         smallint PRIMARY KEY CHECK (id = 1),
	state      bytea NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now()
);`

var plainTable = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$`)

// DeletionState keeps the state of porte/directory's Deletions receiver, its
// cursor and the subjects it handled, in the row id = 1 of a table with the
// columns of [DeletionStateSchema]. It satisfies directory.StateStore, and
// replaces the deletionState type each suite app wrote over that table.
//
// Table names the table when the app called it something else, such as
// deletion_state. It is a lowercase identifier, optionally schema-qualified;
// anything else is refused, since the name goes into the statement.
type DeletionState struct {
	DB    *sql.DB
	Table string
}

// DeletionState returns the receiver state over this store's database, in
// [DeletionStateTable].
func (s *Store) DeletionState() DeletionState {
	return DeletionState{DB: s.db}
}

func (s DeletionState) table() (string, error) {
	if s.Table == "" {
		return DeletionStateTable, nil
	}
	if !plainTable.MatchString(s.Table) {
		return "", fmt.Errorf("porte/pg: %q is not a plain table name", s.Table)
	}
	return s.Table, nil
}

// Load returns the saved state, or nil before the first save.
func (s DeletionState) Load(ctx context.Context) ([]byte, error) {
	table, err := s.table()
	if err != nil {
		return nil, err
	}
	var state []byte
	err = s.DB.QueryRowContext(ctx, `SELECT state FROM `+table+` WHERE id = 1`).Scan(&state)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("porte/pg: load the deletion state: %w", err)
	}
	return state, nil
}

// Save replaces the saved state.
func (s DeletionState) Save(ctx context.Context, state []byte) error {
	table, err := s.table()
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO `+table+` (id, state, updated_at) VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`, state)
	if err != nil {
		return fmt.Errorf("porte/pg: save the deletion state: %w", err)
	}
	return nil
}
