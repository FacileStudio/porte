package pg_test

import (
	"context"
	"testing"

	"github.com/FacileStudio/porte/pg"
)

func TestDeletionStateRoundTripsInTheAppsTable(t *testing.T) {
	store, db := open(t)
	ctx := context.Background()
	for _, statement := range []string{
		`DROP TABLE IF EXISTS directory_deletion_state`,
		`DROP TABLE IF EXISTS deletion_state`,
		pg.DeletionStateSchema,
		`CREATE TABLE deletion_state (LIKE directory_deletion_state INCLUDING ALL)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	for name, state := range map[string]pg.DeletionState{
		"default table": store.DeletionState(),
		"named table":   {DB: db, Table: "deletion_state"},
	} {
		if got, err := state.Load(ctx); err != nil || got != nil {
			t.Fatalf("%s: Load before a save = %q, %v, want nil, nil", name, got, err)
		}
		for _, saved := range []string{`{"cursor":"first"}`, `{"cursor":"second"}`} {
			if err := state.Save(ctx, []byte(saved)); err != nil {
				t.Fatalf("%s: Save: %v", name, err)
			}
			if got, err := state.Load(ctx); err != nil || string(got) != saved {
				t.Fatalf("%s: Load = %q, %v, want %q", name, got, err, saved)
			}
		}
	}
}

func TestDeletionStateRefusesATableNameThatIsNotAnIdentifier(t *testing.T) {
	state := pg.DeletionState{Table: "deletion_state; DROP TABLE porte_users"}
	if _, err := state.Load(context.Background()); err == nil {
		t.Fatal("Load accepted a table name carrying a statement")
	}
	if err := state.Save(context.Background(), []byte("{}")); err == nil {
		t.Fatal("Save accepted a table name carrying a statement")
	}
}
