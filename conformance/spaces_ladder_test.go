package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/FacileStudio/porte/spaces"
)

var ladderRoles = []spaces.Role{spaces.RoleMember, spaces.RoleAdmin, spaces.RoleOwner, "guest", ""}

type members []spaces.Membership

func (m members) Membership(_ context.Context, spaceID, userID string) (spaces.Membership, error) {
	for _, member := range m {
		if member.SpaceID == spaceID && member.UserID == userID {
			return member, nil
		}
	}
	return spaces.Membership{}, spaces.ErrNotMember
}

func (m members) Memberships(context.Context, string) ([]spaces.Membership, error) { return m, nil }

func (m members) CountRole(_ context.Context, spaceID string, role spaces.Role) (int, error) {
	count := 0
	for _, member := range m {
		if member.SpaceID == spaceID && member.Role == role {
			count++
		}
	}
	return count, nil
}

func fixture() members {
	return members{
		{SpaceID: "s1", UserID: "owner", Role: spaces.RoleOwner},
		{SpaceID: "s1", UserID: "admin", Role: spaces.RoleAdmin},
		{SpaceID: "s1", UserID: "member", Role: spaces.RoleMember},
		{SpaceID: "s1", UserID: "ghost", Role: "guest"},
		{SpaceID: "s2", UserID: "owner", Role: spaces.RoleOwner},
		{SpaceID: "s2", UserID: "co-owner", Role: spaces.RoleOwner},
	}
}

func errorCode(err error) any {
	for code, sentinel := range map[string]error{
		"not_member": spaces.ErrNotMember, "forbidden": spaces.ErrForbidden,
		"sole_owner": spaces.ErrSoleOwner, "unknown_role": spaces.ErrUnknownRole,
	} {
		if errors.Is(err, sentinel) {
			return code
		}
	}
	if err != nil {
		return err.Error()
	}
	return nil
}

func atLeastCases() []testCase {
	ladder := spaces.Default()
	var cases []testCase
	for _, have := range ladderRoles {
		for _, min := range ladderRoles {
			cases = append(cases, testCase{
				Name:  "at_least " + label(have) + " >= " + label(min),
				Input: map[string]any{"kind": "at_least", "have": have, "min": min},
				Want:  map[string]bool{"allowed": ladder.AtLeast(have, min)},
			})
		}
	}
	return cases
}

func actorScopes(t *testing.T, guard spaces.Guard) map[string]spaces.Scope {
	t.Helper()
	scopes := map[string]spaces.Scope{"unresolved": {UserID: "owner", SpaceID: "s1", Role: spaces.RoleOwner}}
	for _, actor := range [][2]string{{"owner", "s1"}, {"admin", "s1"}, {"member", "s1"}, {"owner", ""}} {
		scope, err := guard.Resolve(context.Background(), actor[0], actor[1])
		if err != nil {
			t.Fatalf("resolving %v: %v", actor, err)
		}
		name := actor[0]
		if actor[1] == "" {
			name = "personal"
		}
		scopes[name] = scope
	}
	return scopes
}

func TestSpacesLadderVector(t *testing.T) {
	guard := spaces.Guard{Store: fixture()}
	cases := atLeastCases()
	cases = append(cases, assignCases(t, guard)...)
	cases = append(cases, guardCases(guard)...)
	pin(t, "spaces_ladder", map[string]any{
		"ladder":      spaces.Default().Roles(),
		"memberships": membershipView(),
		"actors": map[string]string{
			"owner": "owner of s1, resolved", "admin": "admin of s1, resolved", "member": "member of s1, resolved",
			"personal": "owner, personal scope (no space)", "unresolved": "a Scope literal claiming owner of s1, never resolved",
		},
	}, cases)
}

func label[S ~string](value S) string {
	if value == "" {
		return "(empty)"
	}
	return string(value)
}

func membershipView() []map[string]string {
	var view []map[string]string
	for _, member := range fixture() {
		view = append(view, map[string]string{"space": member.SpaceID, "user": member.UserID, "role": string(member.Role)})
	}
	return view
}
