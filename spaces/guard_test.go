package spaces_test

import (
	"context"
	"errors"
	"testing"

	"github.com/FacileStudio/porte/spaces"
	"github.com/FacileStudio/porte/spaces/spacestest"
)

// The most natural Store is `SELECT role FROM ... WHERE space_id=$1 AND
// user_id=$2`, which scans the role alone and leaves both ids empty. Treating
// an absent id as agreement disarms the cross-check for exactly that store.
func TestResolveRefusesARowWithNoIDs(t *testing.T) {
	guard := spaces.Guard{Store: wrongRow{spaces.Membership{Role: spaces.RoleOwner}}}

	if _, err := guard.Resolve(context.Background(), "u", "s"); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Resolve against a row carrying no ids = %v, want ErrNotMember", err)
	}
}

func TestResolveRefusesARowMissingOneID(t *testing.T) {
	cases := []spaces.Membership{
		{UserID: "u", Role: spaces.RoleOwner},
		{SpaceID: "s", Role: spaces.RoleOwner},
	}
	for _, row := range cases {
		guard := spaces.Guard{Store: wrongRow{row}}
		if _, err := guard.Resolve(context.Background(), "u", "s"); !errors.Is(err, spaces.ErrNotMember) {
			t.Fatalf("Resolve against %+v = %v, want ErrNotMember", row, err)
		}
	}
}

// A caller that ignores the error and branches on Personal must not run the
// personal-data path for user "".
func TestUnresolvedScopeIsNotPersonal(t *testing.T) {
	if (spaces.Scope{}).Personal() {
		t.Fatal("the zero Scope reports as personal scope")
	}
	forged := spaces.Scope{UserID: "mallory", SpaceID: "victim", Role: spaces.RoleOwner}
	if forged.Resolved() {
		t.Fatal("a hand-built Scope reports as resolved")
	}

	scope, err := spaces.Guard{Store: spacestest.NewMemory()}.Resolve(context.Background(), "u", "")
	if err != nil || !scope.Personal() || !scope.Resolved() {
		t.Fatalf("Resolve(u, \"\") = %+v, %v, want a resolved personal scope", scope, err)
	}
}

// A Store with a bad join hands back another user's memberships, and the space
// switcher renders exactly this list.
func TestSpacesDropsRowsBelongingToAnotherUser(t *testing.T) {
	store := wrongRow{spaces.Membership{SpaceID: "a", UserID: "someone-else", Role: spaces.RoleAdmin}}

	held, err := spaces.Guard{Store: store}.Spaces(context.Background(), "u")
	if err != nil {
		t.Fatalf("Spaces = %v", err)
	}
	if len(held) != 0 {
		t.Fatalf("Spaces returned %+v, want none of another user's rows", held)
	}
}

func TestSpacesDropsRowsWithMissingIDs(t *testing.T) {
	store := wrongRow{spaces.Membership{UserID: "u", Role: spaces.RoleAdmin}}

	held, err := spaces.Guard{Store: store}.Spaces(context.Background(), "u")
	if err != nil {
		t.Fatalf("Spaces = %v", err)
	}
	if len(held) != 0 {
		t.Fatalf("Spaces returned %+v, want no row missing a space id", held)
	}
}

func TestRequireRefusesAnEmptySpaceID(t *testing.T) {
	guard := spaces.Guard{Store: spacestest.NewMemory()}

	scope, err := guard.Require(context.Background(), "u", "", spaces.RoleMember)
	if !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Require with an empty space id = %+v, %v, want ErrNotMember", scope, err)
	}
	if scope != (spaces.Scope{}) {
		t.Fatalf("Require refused but returned %+v, want the zero Scope", scope)
	}
}

func TestAssignableByRefusesAnUnresolvedScope(t *testing.T) {
	guard := spaces.Guard{Store: spacestest.NewMemory()}

	forged := spaces.Scope{UserID: "mallory", SpaceID: "victim", Role: spaces.RoleOwner}
	if guard.AssignableBy(forged, spaces.RoleOwner) {
		t.Fatal("a hand-built Scope granted the top rank")
	}
	if guard.AssignableBy(spaces.Scope{}, spaces.RoleMember) {
		t.Fatal("the zero Scope granted a rank")
	}
}

func TestAssignableByOnAResolvedScope(t *testing.T) {
	store := spacestest.NewMemory()
	seed(t, store, spaces.Membership{SpaceID: "s", UserID: "u", Role: spaces.RoleAdmin})

	guard := spaces.Guard{Store: store}
	scope, err := guard.Require(context.Background(), "u", "s", spaces.RoleAdmin)
	if err != nil {
		t.Fatalf("Require = %v", err)
	}
	if !guard.AssignableBy(scope, spaces.RoleAdmin) {
		t.Fatal("an admin could not appoint a peer admin")
	}
	if guard.AssignableBy(scope, spaces.RoleOwner) {
		t.Fatal("an admin could mint an owner")
	}
}

// An app that builds its ladder from a misconfigured config must refuse
// everything rather than silently inherit the suite vocabulary.
func TestAnExplicitlyEmptyLadderIsNotTheDefault(t *testing.T) {
	store := spacestest.NewMemory()
	seed(t, store, spaces.Membership{SpaceID: "s", UserID: "u", Role: spaces.RoleOwner})

	guard := spaces.Guard{Store: store, Ladder: spaces.NewLadder()}
	if _, err := guard.Require(context.Background(), "u", "s", spaces.RoleOwner); !errors.Is(err, spaces.ErrUnknownRole) {
		t.Fatalf("Require on an explicitly empty ladder = %v, want ErrUnknownRole", err)
	}

	fallback := spaces.Guard{Store: store}
	if _, err := fallback.Require(context.Background(), "u", "s", spaces.RoleOwner); err != nil {
		t.Fatalf("Require on the zero Ladder = %v, want the default ladder", err)
	}
}
