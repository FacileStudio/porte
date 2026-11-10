package conformance

import (
	"context"
	"testing"

	"github.com/FacileStudio/porte/spaces"
)

func assignCases(t *testing.T, guard spaces.Guard) []testCase {
	t.Helper()
	scopes := actorScopes(t, guard)
	var cases []testCase
	for _, actor := range sortedKeys(scopes) {
		for _, target := range ladderRoles {
			cases = append(cases, testCase{
				Name:  "assignable_by " + actor + " grants " + label(target),
				Input: map[string]any{"kind": "assignable_by", "actor": actor, "target": target},
				Want:  map[string]bool{"allowed": guard.AssignableBy(scopes[actor], target)},
			})
			cases = append(cases, overCases(guard, actor, scopes[actor], target)...)
		}
	}
	return cases
}

func overCases(guard spaces.Guard, actor string, scope spaces.Scope, target spaces.Role) []testCase {
	cases := make([]testCase, 0, len(ladderRoles))
	for _, current := range ladderRoles {
		cases = append(cases, testCase{
			Name:  "assignable_over " + actor + " moves " + label(current) + " to " + label(target),
			Input: map[string]any{"kind": "assignable_over", "actor": actor, "current": current, "target": target},
			Want:  map[string]bool{"allowed": guard.AssignableOver(scope, current, target)},
		})
	}
	return cases
}

func guardCases(guard spaces.Guard) []testCase {
	ctx := context.Background()
	var cases []testCase
	for _, user := range []string{"owner", "admin", "member", "ghost", "stranger", ""} {
		for _, space := range []string{"s1", "s2", ""} {
			cases = append(cases, requireCases(guard, user, space)...)
			cases = append(cases, testCase{
				Name:  "can_leave " + label(user) + " from " + label(space),
				Input: map[string]any{"kind": "can_leave", "user": user, "space": space},
				Want:  map[string]any{"error": errorCode(guard.CanLeave(ctx, user, space))},
			})
		}
	}
	return cases
}

func requireCases(guard spaces.Guard, user, space string) []testCase {
	var cases []testCase
	for _, min := range []spaces.Role{spaces.RoleMember, spaces.RoleAdmin, spaces.RoleOwner, "guest"} {
		scope, err := guard.Require(context.Background(), user, space, min)
		cases = append(cases, testCase{
			Name:  "require " + label(user) + " in " + label(space) + " at " + label(min),
			Input: map[string]any{"kind": "require", "user": user, "space": space, "min": min},
			Want:  map[string]any{"error": errorCode(err), "role": scope.Role},
		})
	}
	return cases
}
