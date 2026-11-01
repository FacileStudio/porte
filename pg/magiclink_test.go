package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/magiclink/magiclinktest"
)

func TestMagicLinkStoreConforms(t *testing.T) {
	store, db := open(t)
	if _, err := db.ExecContext(context.Background(), "DELETE FROM porte_magic_links"); err != nil {
		t.Fatalf("clean: %v", err)
	}
	counter := 0
	magiclinktest.Conformance(t,
		func(t *testing.T) porte.MagicLinkStore {
			if _, err := db.ExecContext(context.Background(), "DELETE FROM porte_magic_links"); err != nil {
				t.Fatalf("clean: %v", err)
			}
			return store.MagicLinks()
		},
		func(t *testing.T) int64 {
			counter++
			var id int64
			err := db.QueryRowContext(context.Background(),
				`INSERT INTO porte_users (email) VALUES ($1) RETURNING id`,
				fmt.Sprintf("magic-%d@facile.test", counter)).Scan(&id)
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			return id
		},
	)
}
