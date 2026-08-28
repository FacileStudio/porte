package spacestest

import (
	"context"
	"errors"
	"testing"

	"github.com/FacileStudio/porte/spaces"
)

func testOnlyKey(t *testing.T, f fixture) {
	ctx := context.Background()

	scope, err := f.guard.Resolve(ctx, UserOutsider, SpaceA)
	if !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Resolve for a non-member = %v, want ErrNotMember", err)
	}
	if scope.Resolved() {
		t.Fatalf("Resolve refused but returned %+v, want an unresolved Scope", scope)
	}

	if _, err := f.guard.Require(ctx, UserOutsider, SpaceA, f.bottom); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Require for a non-member = %v, want ErrNotMember", err)
	}

	scope, err = f.guard.Require(ctx, UserMember, SpaceA, f.bottom)
	if err != nil || scope.Role != f.bottom || !scope.Resolved() {
		t.Fatalf("Require(%q, %q) = %+v, %v, want the bottom-rank scope", UserMember, f.bottom, scope, err)
	}

	scope, err = f.guard.Require(ctx, UserMember, SpaceA, f.middle)
	if !errors.Is(err, spaces.ErrForbidden) {
		t.Fatalf("Require(%q, %q) = %v, want ErrForbidden", UserMember, f.middle, err)
	}
	if scope.Resolved() {
		t.Fatalf("Require refused but returned %+v, want an unresolved Scope", scope)
	}
}

func testSpaceIDChecked(t *testing.T, f fixture) {
	ctx := context.Background()

	if (spaces.Scope{}).Personal() || (spaces.Scope{}).Resolved() {
		t.Fatal("the zero Scope reports as resolved or personal, so an ignored error yields a usable scope")
	}

	scope, err := f.guard.Resolve(ctx, UserOwner, "")
	if err != nil {
		t.Fatalf("Resolve with an empty space id = %v, want personal scope", err)
	}
	if !scope.Personal() || scope.SpaceID != "" || scope.Role != "" || scope.UserID != UserOwner {
		t.Fatalf("Resolve(%q, \"\") = %+v, want a personal scope for that user carrying no space and no role", UserOwner, scope)
	}

	if _, err := f.guard.Resolve(ctx, "", ""); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Resolve with no user = %v, want ErrNotMember", err)
	}
	if _, err := f.guard.Require(ctx, UserOwner, "", f.bottom); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Require with an empty space id = %v, want ErrNotMember", err)
	}

	testSpaceIDIsScoped(t, f)
}

func testSpaceIDIsScoped(t *testing.T, f fixture) {
	ctx := context.Background()

	scope, err := f.guard.Resolve(ctx, UserAdmin, SpaceA)
	if err != nil {
		t.Fatalf("Resolve for a member = %v", err)
	}
	if scope.SpaceID != SpaceA || scope.Role != f.middle || scope.Personal() {
		t.Fatalf("Resolve(%q, A) = %+v, want the middle-rank scope on A", UserAdmin, scope)
	}

	if _, err := f.guard.Resolve(ctx, UserAdmin, SpaceB); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("Resolve(a member of A only, B) = %v, want ErrNotMember", err)
	}
}

func testReachableOwner(t *testing.T, f fixture) {
	ctx := context.Background()

	if err := f.guard.CanLeave(ctx, UserOwner, SpaceA); !errors.Is(err, spaces.ErrSoleOwner) {
		t.Fatalf("CanLeave(sole top rank) = %v, want ErrSoleOwner", err)
	}
	if err := f.guard.CanLeave(ctx, UserOwner, SpaceB); err != nil {
		t.Fatalf("CanLeave(one of two at the top rank) = %v, want nil", err)
	}
	if err := f.guard.CanLeave(ctx, UserMember, SpaceA); err != nil {
		t.Fatalf("CanLeave(bottom rank) = %v, want nil", err)
	}
	if err := f.guard.CanLeave(ctx, UserAdmin, SpaceA); err != nil {
		t.Fatalf("CanLeave(middle rank) = %v, want nil", err)
	}
	if err := f.guard.CanLeave(ctx, UserOutsider, SpaceA); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("CanLeave(non-member) = %v, want ErrNotMember", err)
	}
	if err := f.guard.CanLeave(ctx, UserOwner, ""); !errors.Is(err, spaces.ErrNotMember) {
		t.Fatalf("CanLeave with an empty space id = %v, want ErrNotMember", err)
	}
}

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

func resolved(t *testing.T, f fixture, userID, spaceID string) spaces.Scope {
	t.Helper()

	scope, err := f.guard.Resolve(context.Background(), userID, spaceID)
	if err != nil {
		t.Fatalf("Resolve(%q, %q) = %v, want a scope", userID, spaceID, err)
	}
	return scope
}
