package spacestest

import (
	"context"
	"testing"

	"github.com/FacileStudio/porte/spaces"
)

// The fixture Conformance seeds. Space A has one member at each of three
// ranks; space B has two members at the top rank, which is the only difference
// that makes CanLeave interesting.
//
// The user ids are named after the suite's roles for readability. Under a
// custom ladder they still name the top, middle and bottom ranks of that
// ladder rather than owner, admin and member.
const (
	SpaceA = "space-a"
	SpaceB = "space-b"

	UserOwner    = "user-owner"
	UserAdmin    = "user-admin"
	UserMember   = "user-member"
	UserCoOwner  = "user-co-owner"
	UserOutsider = "user-outsider"
)

// fixture is one seeded store, the guard over it, and the three ranks the
// subtests exercise, taken from the ladder under test.
type fixture struct {
	guard  spaces.Guard
	rows   []spaces.Membership
	top    spaces.Role
	middle spaces.Role
	bottom spaces.Role
}

// Conformance runs the invariants of spaces.Guard against a Store
// implementation, on the suite's default ladder. newStore must return an empty
// store that also implements Seeder; each subtest gets a fresh one.
//
// It is deliberately small. It does not test the app's CRUD, its routes or
// its wire shapes — only the rules whose drift is a security bug, which are
// the only rules the spaces package claims.
func Conformance(t *testing.T, newStore func() spaces.Store) {
	t.Helper()
	ConformanceWithLadder(t, newStore, spaces.Default())
}

// ConformanceWithLadder is Conformance against an app's own role vocabulary.
// Vision ranks owner|admin|editor|viewer and is the reason Ladder is
// configurable at all; running the suite on the default ladder would prove
// nothing about the guard Vision actually ships.
//
// The ladder must rank at least three roles: the suite needs a top, a middle
// and a bottom rank to tell a refusal from an escalation.
func ConformanceWithLadder(t *testing.T, newStore func() spaces.Store, ladder spaces.Ladder) {
	t.Helper()

	roles := ladder.Roles()
	if len(roles) < 3 {
		t.Fatalf("the ladder ranks %d roles, the suite needs at least three distinct ranks", len(roles))
	}

	run := func(name string, test func(*testing.T, fixture)) {
		t.Run(name, func(t *testing.T) {
			test(t, seeded(t, newStore, ladder, roles))
		})
	}
	run("membership is the only key", testOnlyKey)
	run("a space id is checked before it is usable", testSpaceIDChecked)
	run("a space keeps a reachable owner", testReachableOwner)
	run("no privilege escalation", testNoEscalation)
	run("absence is an error", testAbsenceIsError)
	run("the store returns its own rows, unaltered", testRowsAreFaithful)
}

func seeded(t *testing.T, newStore func() spaces.Store, ladder spaces.Ladder, roles []spaces.Role) fixture {
	t.Helper()

	store := newStore()
	seeder, ok := store.(Seeder)
	if !ok {
		t.Fatalf("store %T does not implement spacestest.Seeder, the suite cannot build its fixture", store)
	}

	f := fixture{
		guard:  spaces.Guard{Store: store, Ladder: ladder},
		top:    roles[len(roles)-1],
		middle: roles[len(roles)-2],
		bottom: roles[0],
	}
	f.rows = []spaces.Membership{
		{SpaceID: SpaceA, UserID: UserOwner, Role: f.top},
		{SpaceID: SpaceA, UserID: UserAdmin, Role: f.middle},
		{SpaceID: SpaceA, UserID: UserMember, Role: f.bottom},
		{SpaceID: SpaceB, UserID: UserOwner, Role: f.top},
		{SpaceID: SpaceB, UserID: UserCoOwner, Role: f.top},
	}
	for _, member := range f.rows {
		if err := seeder.Seed(context.Background(), member); err != nil {
			t.Fatalf("seed %s/%s: %v", member.SpaceID, member.UserID, err)
		}
	}
	return f
}
