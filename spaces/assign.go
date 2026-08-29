package spaces

// AssignableBy reports whether the actor holding actor may grant target to
// somebody who holds no role yet — an invitation, or adding a member to a
// space. It is false when target outranks actor, so an admin cannot mint an
// owner and then be promoted by it.
//
// It is the narrower of the two checks and it is the wrong one for a member
// screen. It sees only the role being granted, never the role the person
// already holds, so AssignableBy(adminScope, RoleMember) is true whoever that
// role is about to land on — including the space's owner. Use AssignableOver
// whenever an existing member's role is being changed; reach for this one only
// on the path where there is no current role to outrank.
//
// It takes a Scope rather than a Role so that the actor's rank cannot be
// asserted by the caller. Two plain Roles invite passing both straight off the
// wire, which checks the request against itself; a Scope only exists if
// Resolve built it, and an unresolved or personal one grants nothing. The
// caller already holds the Scope that Require returned.
//
// Granting one's own rank is allowed: an admin may appoint a peer admin,
// which is what every adopter's member screen already does.
func (g Guard) AssignableBy(actor Scope, target Role) bool {
	if !actor.Resolved() || actor.Personal() {
		return false
	}
	return g.ladder().AtLeast(actor.Role, target)
}

// AssignableOver reports whether the actor may change an existing member from
// current to target. It is the complete check, and the one a member screen
// calls: false unless the actor ranks at or above both the role being taken
// away and the role being granted.
//
// The second half is what AssignableBy cannot see. Guarding only the grant
// leaves the mirror image open — an admin handing "member" to the owner, which
// costs the space every account that can administer it and cannot be undone by
// anyone left inside. Agenda shipped exactly that, and review found it here
// before any adopter did.
//
// current must come from the app's own membership row, never from the request.
// It is a plain Role and not a Scope because the caller has just read that row,
// usually inside the transaction that is about to update it, and forcing a
// second lookup through the Store would hand back a value that can change
// before the write lands. A current role the ladder does not rank is refused
// rather than scored zero, so a typo in a role column closes the door.
//
// It counts nobody. An owner demoting the last owner passes here and empties
// the top rank, which is the same shape CanLeave refuses with ErrSoleOwner; an
// app that offers self-demotion owes it the same count, under the same lock.
func (g Guard) AssignableOver(actor Scope, current, target Role) bool {
	if !g.ladder().Valid(current) {
		return false
	}
	return g.AssignableBy(actor, current) && g.AssignableBy(actor, target)
}
