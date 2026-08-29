package spacestest

import (
	"testing"

	"github.com/FacileStudio/porte/spaces"
)

type assignCase struct {
	name   string
	actor  spaces.Scope
	target spaces.Role
	want   bool
}

func testNoEscalation(t *testing.T, f fixture) {
	for _, tc := range assignCases(t, f) {
		if got := f.guard.AssignableBy(tc.actor, tc.target); got != tc.want {
			t.Errorf("%s: AssignableBy(%+v, %q) = %v, want %v", tc.name, tc.actor, tc.target, got, tc.want)
		}
	}
	testNoDemotion(t, f)
}

func testNoDemotion(t *testing.T, f fixture) {
	middle := resolved(t, f, UserAdmin, SpaceA)

	if f.guard.AssignableOver(middle, f.top, f.bottom) {
		t.Errorf("the middle rank demoted the top rank")
	}
	if !f.guard.AssignableOver(middle, f.bottom, f.middle) {
		t.Errorf("the middle rank could not promote the bottom rank to a peer")
	}
}

func assignCases(t *testing.T, f fixture) []assignCase {
	t.Helper()

	top := resolved(t, f, UserOwner, SpaceA)
	middle := resolved(t, f, UserAdmin, SpaceA)
	bottom := resolved(t, f, UserMember, SpaceA)
	personal := resolved(t, f, UserOwner, "")

	return []assignCase{
		{"the middle rank cannot mint the top", middle, f.top, false},
		{"the bottom rank cannot mint the middle", bottom, f.middle, false},
		{"the bottom rank cannot mint the top", bottom, f.top, false},
		{"the middle rank may appoint a peer", middle, f.middle, true},
		{"the middle rank may grant below itself", middle, f.bottom, true},
		{"the top rank may grant its own", top, f.top, true},
		{"no rank grants an unranked role", top, spaces.Role("porte-conformance-unranked"), false},
		{"personal scope grants nothing", personal, f.bottom, false},
		{"the zero Scope grants nothing", spaces.Scope{}, f.bottom, false},
		{"a hand-built Scope grants nothing", forged(f), f.top, false},
	}
}

func forged(f fixture) spaces.Scope {
	return spaces.Scope{UserID: UserOutsider, SpaceID: SpaceA, Role: f.top}
}
