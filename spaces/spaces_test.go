package spaces_test

import (
	"context"
	"errors"
	"testing"

	"github.com/FacileStudio/porte/spaces"
	"github.com/FacileStudio/porte/spaces/spacestest"
)

func TestConformance(t *testing.T) {
	spacestest.Conformance(t, func() spaces.Store { return spacestest.NewMemory() })
}

// Vision ranks owner|admin|editor|viewer, which is why Ladder is configurable
// and why the conformance suite has to accept one.
func TestConformanceWithACustomLadder(t *testing.T) {
	spacestest.ConformanceWithLadder(t,
		func() spaces.Store { return spacestest.NewMemory() },
		spaces.NewLadder("viewer", "editor", spaces.RoleAdmin, spaces.RoleOwner))
}

func TestLadderRefusesUnknownRoles(t *testing.T) {
	ladder := spaces.Default()

	if ladder.Valid("root") {
		t.Fatal("Valid(root) = true on the default ladder")
	}
	if ladder.AtLeast("root", spaces.RoleMember) {
		t.Fatal("an unranked role satisfied the member floor")
	}
	if ladder.AtLeast(spaces.RoleOwner, "root") {
		t.Fatal("owner satisfied an unranked floor")
	}
	if got := ladder.Top(); got != spaces.RoleOwner {
		t.Fatalf("Top() = %q, want owner", got)
	}
	if got := len(ladder.Roles()); got != 3 {
		t.Fatalf("Roles() has %d entries, want 3", got)
	}
	if empty := (spaces.Ladder{}); empty.Valid(spaces.RoleOwner) || empty.Top() != "" || empty.Configured() {
		t.Fatal("the zero Ladder ranks something, or reports itself as configured")
	}
	if !spaces.NewLadder().Configured() {
		t.Fatal("NewLadder() is indistinguishable from the zero Ladder")
	}
}

func TestNewLadderDropsDuplicates(t *testing.T) {
	ladder := spaces.NewLadder(spaces.RoleMember, spaces.RoleAdmin, spaces.RoleMember, "")
	if got := len(ladder.Roles()); got != 2 {
		t.Fatalf("Roles() has %d entries, want 2", got)
	}
	if got := ladder.Top(); got != spaces.RoleAdmin {
		t.Fatalf("Top() = %q, want admin", got)
	}
}

// Vision gates every write on owner|admin|editor, which is why the ladder is
// configurable at all. This is that ladder, run through the same guard.
func TestCustomLadder(t *testing.T) {
	ctx := context.Background()
	store := spacestest.NewMemory()
	seed(t, store,
		spaces.Membership{SpaceID: "site", UserID: "u-editor", Role: "editor"},
		spaces.Membership{SpaceID: "site", UserID: "u-viewer", Role: "viewer"},
		spaces.Membership{SpaceID: "site", UserID: "u-owner", Role: spaces.RoleOwner},
	)

	guard := spaces.Guard{
		Store:  store,
		Ladder: spaces.NewLadder("viewer", "editor", spaces.RoleAdmin, spaces.RoleOwner),
	}

	if _, err := guard.Require(ctx, "u-editor", "site", "editor"); err != nil {
		t.Fatalf("an editor was refused a write: %v", err)
	}
	if _, err := guard.Require(ctx, "u-viewer", "site", "editor"); !errors.Is(err, spaces.ErrForbidden) {
		t.Fatalf("Require(viewer, editor) = %v, want ErrForbidden", err)
	}
	editor, err := guard.Require(ctx, "u-editor", "site", "editor")
	if err != nil {
		t.Fatalf("Require(editor) = %v", err)
	}
	if guard.AssignableBy(editor, spaces.RoleAdmin) {
		t.Fatal("an editor could grant admin")
	}
	if err := guard.CanLeave(ctx, "u-owner", "site"); !errors.Is(err, spaces.ErrSoleOwner) {
		t.Fatalf("CanLeave(sole owner) = %v, want ErrSoleOwner on a custom ladder", err)
	}
	if err := guard.CanLeave(ctx, "u-editor", "site"); err != nil {
		t.Fatalf("CanLeave(editor) = %v, want nil", err)
	}
}

func TestRequireRefusesAnUnknownMinimum(t *testing.T) {
	store := spacestest.NewMemory()
	seed(t, store, spaces.Membership{SpaceID: "s", UserID: "u", Role: spaces.RoleOwner})

	guard := spaces.Guard{Store: store}
	if _, err := guard.Require(context.Background(), "u", "s", "root"); !errors.Is(err, spaces.ErrUnknownRole) {
		t.Fatalf("Require with an unranked minimum = %v, want ErrUnknownRole", err)
	}
}

// A Store with a wrong WHERE clause must fail the lookup, never hand back a
// membership in a space the caller did not ask about.
func TestResolveRefusesAMismatchedRow(t *testing.T) {
	guard := spaces.Guard{Store: wrongRow{spaces.Membership{
		SpaceID: "other-space", UserID: "u", Role: spaces.RoleOwner,
	}}}

	if _, err := guard.Resolve(context.Background(), "u", "s"); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Resolve against a mismatched row = %v, want ErrNotMember", err)
	}
}

func TestResolveRefusesAnUnrankedStoredRole(t *testing.T) {
	guard := spaces.Guard{Store: wrongRow{spaces.Membership{
		SpaceID: "s", UserID: "u", Role: "root",
	}}}

	if _, err := guard.Resolve(context.Background(), "u", "s"); !errors.Is(err, spaces.ErrUnknownRole) {
		t.Fatalf("Resolve against an unranked role = %v, want ErrUnknownRole", err)
	}
}

func TestSpacesDropsUnrankedRows(t *testing.T) {
	store := spacestest.NewMemory()
	seed(t, store,
		spaces.Membership{SpaceID: "a", UserID: "u", Role: spaces.RoleAdmin},
		spaces.Membership{SpaceID: "b", UserID: "u", Role: "root"},
	)

	held, err := spaces.Guard{Store: store}.Spaces(context.Background(), "u")
	if err != nil {
		t.Fatalf("Spaces = %v", err)
	}
	if len(held) != 1 || held[0].SpaceID != "a" {
		t.Fatalf("Spaces returned %+v, want only the admin row on a", held)
	}
}

func seed(t *testing.T, store *spacestest.Memory, members ...spaces.Membership) {
	t.Helper()
	for _, member := range members {
		if err := store.Seed(context.Background(), member); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

// wrongRow is a deliberately dishonest Store: it answers every lookup with the
// same row, whatever was asked for.
type wrongRow struct{ row spaces.Membership }

func (w wrongRow) Membership(context.Context, string, string) (spaces.Membership, error) {
	return w.row, nil
}

func (w wrongRow) Memberships(context.Context, string) ([]spaces.Membership, error) {
	return []spaces.Membership{w.row}, nil
}

func (w wrongRow) CountRole(context.Context, string, spaces.Role) (int, error) { return 1, nil }
