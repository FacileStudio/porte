package spaces_test

import (
	"context"
	"testing"

	"github.com/FacileStudio/porte/spaces"
	"github.com/FacileStudio/porte/spaces/spacestest"
)

// Agenda shipped this exact hole: the rank check guarded the role being granted
// and never looked at the role being taken away, so an admin could hand
// "member" to the owner and strand the space with nobody who can administer it.
// AssignableBy alone answers true here, which is why it is not the method a
// member screen calls.
func TestAnAdminCannotDemoteTheOwner(t *testing.T) {
	guard, actor := admin(t)

	if !guard.AssignableBy(actor, spaces.RoleMember) {
		t.Fatal("AssignableBy refused a grant of member, so this no longer pins the gap")
	}
	if guard.AssignableOver(actor, spaces.RoleOwner, spaces.RoleMember) {
		t.Fatal("an admin demoted the owner to member")
	}
}

type overCase struct {
	name            string
	actor           spaces.Scope
	current, target spaces.Role
	want            bool
}

func TestAssignableOver(t *testing.T) {
	guard, cases := overCases(t)

	for _, tc := range cases {
		if got := guard.AssignableOver(tc.actor, tc.current, tc.target); got != tc.want {
			t.Errorf("%s: AssignableOver(%+v, %q, %q) = %v, want %v",
				tc.name, tc.actor, tc.current, tc.target, got, tc.want)
		}
	}
}

func overCases(t *testing.T) (spaces.Guard, []overCase) {
	t.Helper()

	guard, actor := admin(t)
	owner, err := guard.Require(context.Background(), "owner", "s", spaces.RoleOwner)
	if err != nil {
		t.Fatalf("Require = %v", err)
	}
	personal, err := guard.Resolve(context.Background(), "admin", "")
	if err != nil {
		t.Fatalf("Resolve = %v", err)
	}
	forged := spaces.Scope{UserID: "mallory", SpaceID: "s", Role: spaces.RoleOwner}

	return guard, []overCase{
		{"an admin cannot demote the owner", actor, spaces.RoleOwner, spaces.RoleMember, false},
		{"an admin cannot promote the owner", actor, spaces.RoleOwner, spaces.RoleOwner, false},
		{"an admin may appoint a peer admin", actor, spaces.RoleMember, spaces.RoleAdmin, true},
		{"an admin may demote a peer admin", actor, spaces.RoleAdmin, spaces.RoleMember, true},
		{"an admin may not mint an owner", actor, spaces.RoleMember, spaces.RoleOwner, false},
		{"an owner may demote an owner", owner, spaces.RoleOwner, spaces.RoleMember, true},
		{"an unranked current role refuses", actor, "root", spaces.RoleMember, false},
		{"an unranked target role refuses", actor, spaces.RoleMember, "root", false},
		{"an empty current role refuses", actor, "", spaces.RoleMember, false},
		{"a hand-built Scope grants nothing", forged, spaces.RoleMember, spaces.RoleMember, false},
		{"the zero Scope grants nothing", spaces.Scope{}, spaces.RoleMember, spaces.RoleMember, false},
		{"personal scope grants nothing", personal, spaces.RoleMember, spaces.RoleMember, false},
	}
}

// Vision ranks viewer|editor|admin|owner, so the rule has to be a comparison
// inside the app's own ladder rather than anything about the suite's three.
func TestAssignableOverOnACustomLadder(t *testing.T) {
	store := spacestest.NewMemory()
	seed(t, store, spaces.Membership{SpaceID: "site", UserID: "u", Role: "editor"})

	guard := spaces.Guard{
		Store:  store,
		Ladder: spaces.NewLadder("viewer", "editor", spaces.RoleAdmin, spaces.RoleOwner),
	}
	editor, err := guard.Require(context.Background(), "u", "site", "editor")
	if err != nil {
		t.Fatalf("Require = %v", err)
	}

	if !guard.AssignableOver(editor, "viewer", "editor") {
		t.Fatal("an editor could not promote a viewer to peer")
	}
	if guard.AssignableOver(editor, spaces.RoleAdmin, "viewer") {
		t.Fatal("an editor demoted an admin")
	}
	if guard.AssignableOver(editor, "viewer", spaces.RoleMember) {
		t.Fatal("a role this ladder does not rank was granted")
	}
}

func admin(t *testing.T) (spaces.Guard, spaces.Scope) {
	t.Helper()

	store := spacestest.NewMemory()
	seed(t, store,
		spaces.Membership{SpaceID: "s", UserID: "admin", Role: spaces.RoleAdmin},
		spaces.Membership{SpaceID: "s", UserID: "owner", Role: spaces.RoleOwner},
	)

	guard := spaces.Guard{Store: store}
	scope, err := guard.Require(context.Background(), "admin", "s", spaces.RoleAdmin)
	if err != nil {
		t.Fatalf("Require = %v", err)
	}
	return guard, scope
}
