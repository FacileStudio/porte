package spaces

import "slices"

// Ladder orders roles by privilege, ascending. It is the whole of what this
// package knows about what a role means: comparison, never a switch.
//
// It is configurable rather than fixed at three roles because a fixed set
// would not survive first contact. Vision gates every write on
// owner|admin|editor and would have had to keep its own copy of the guard, so
// the package that exists to end the copies would have produced one more.
//
// The zero Ladder is the unset ladder, not an empty one: Valid reports false
// for every role, and Guard substitutes Default for it so the zero Guard is
// usable. A ladder that came out of NewLadder is never the zero value, even
// when it ranks nothing, so NewLadder(cfg.Roles...) over a misconfigured
// config refuses every role instead of silently inheriting the suite's.
type Ladder struct {
	ascending []Role
	built     bool
}

// NewLadder builds a ladder from roles listed least privileged first.
// Duplicates are dropped, keeping the first position each role appears at.
//
// NewLadder() with no roles is a ladder that ranks nothing, and it is distinct
// from the zero Ladder: a Guard holding it refuses every role rather than
// falling back to Default.
func NewLadder(ascending ...Role) Ladder {
	order := make([]Role, 0, len(ascending))
	for _, role := range ascending {
		if role != "" && !slices.Contains(order, role) {
			order = append(order, role)
		}
	}
	return Ladder{ascending: order, built: true}
}

// Default is the suite's ladder: member, then admin, then owner.
//
// It is a function and not a package-level var so that no importer can
// reassign the ladder every other importer's Guard falls back to. A mutable
// global in the package that answers "may this caller act here" is one
// init function away from being an authorization bug.
func Default() Ladder { return NewLadder(RoleMember, RoleAdmin, RoleOwner) }

// Configured reports whether the ladder was built by NewLadder rather than
// left at its zero value. It is what Guard consults before falling back to
// Default, and it is exported so an app that assembles a ladder from its
// configuration can refuse to boot on the unset one.
func (l Ladder) Configured() bool { return l.built }

// Valid reports whether the role is one this ladder ranks. A role it does not
// rank is not a weak role, it is an unknown one, and every check below refuses
// it rather than scoring it zero.
func (l Ladder) Valid(role Role) bool {
	return slices.Contains(l.ascending, role)
}

// AtLeast reports whether have ranks at or above min. It is false when either
// role is unknown to the ladder — a typo in a database column must close a
// door, not open one.
func (l Ladder) AtLeast(have, min Role) bool {
	held := slices.Index(l.ascending, have)
	floor := slices.Index(l.ascending, min)
	return held >= 0 && floor >= 0 && held >= floor
}

// Top returns the ladder's most privileged role, or the empty Role for a
// ladder that ranks nothing. It is what CanLeave protects: the rank a space
// must keep at least one of.
func (l Ladder) Top() Role {
	if len(l.ascending) == 0 {
		return ""
	}
	return l.ascending[len(l.ascending)-1]
}

// Roles returns the ladder's roles, least privileged first.
func (l Ladder) Roles() []Role {
	return slices.Clone(l.ascending)
}
