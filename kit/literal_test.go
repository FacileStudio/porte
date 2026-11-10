package kit_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/kit"
)

const literalWarning = "built as a literal"

func TestALiteralStoreWarnsOncePerProcess(t *testing.T) {
	db := openDB(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	kit.ResetLiteralWarning()
	first := &kit.Store{DB: db, Columns: kit.Columns{Table: "gorm_users"}, Logger: logger}
	second := &kit.Store{DB: db, Columns: kit.Columns{Table: "gorm_users"}, Logger: logger}
	mustSignIn(t, first, claimsFor("sub-1", "camille@facile.studio", true))
	mustSignIn(t, first, claimsFor("sub-1", "camille@facile.studio", true))
	mustSignIn(t, second, claimsFor("sub-2", "dominique@facile.studio", true))
	if _, err := second.BackfillPictures(context.Background(), fakeIssuer); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	out := logs.String()
	if got := strings.Count(out, literalWarning); got != 1 {
		t.Fatalf("literal warnings = %d, logs %q", got, out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "NULL") || !strings.Contains(out, "kit.NewStore") {
		t.Fatalf("logs = %q", out)
	}
}

func TestANewStoreBuiltStoreNeverWarnsAboutLiterals(t *testing.T) {
	db := openDB(t)
	kit.ResetLiteralWarning()
	store, logs := newStore(t, kit.Store{DB: db, Columns: kit.Columns{Admin: "is_admin"}})
	var writes bytes.Buffer
	store.Logger = slog.New(slog.NewTextHandler(&writes, nil))
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	mustSignIn(t, store, claimsFor("sub-1", "camille@facile.studio", true))
	if _, err := store.BackfillPictures(context.Background(), fakeIssuer); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if out := logs + writes.String(); strings.Contains(out, literalWarning) {
		t.Fatalf("a NewStore store warned about a literal: %q", out)
	}
}
