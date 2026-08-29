package spaces

import "context"

// Guard answers the authorization questions against a Store.
//
// Store is required, not optional. A Guard with a nil Store answers personal
// scope and then panics on the first space id, which is a nil dereference in a
// request handler rather than a refusal; construct one with the Store set.
//
// Ladder is optional: the zero Ladder means Default(). A ladder built by
// NewLadder is used as given even when it ranks nothing, so an app that
// derives its vocabulary from configuration refuses everything on a
// misconfiguration instead of silently inheriting the suite's three roles.
//
// There is deliberately no instance-admin bypass, no superuser flag and no
// hook to add one. Membership is the only key: an app that wants staff to
// reach a space grants that staff account a membership, where it is visible in
// the member list and revocable like everything else. A bypass inside this
// package would be invisible to every app that imported it.
type Guard struct {
	Store  Store
	Ladder Ladder
}

func (g Guard) ladder() Ladder {
	if !g.Ladder.Configured() {
		return Default()
	}
	return g.Ladder
}

// Resolve turns a user and a requested space id into a Scope.
//
// An empty space id is personal scope and returns without touching the Store.
// Any non-empty id goes through Store.Membership, so the only way to hold a
// resolved Scope carrying a space id is to be a member of that space: a caller
// who is not gets ErrNotMember and the zero Scope, whatever else it may be
// inside the app.
//
// The returned Scope is built from the arguments, not from the row. The row
// must carry both ids and both must equal what was asked for; a row missing an
// id, or disagreeing on one, is refused as ErrNotMember. An absent id is not
// agreement, because the most natural Store selects the role alone and would
// otherwise disarm the whole check. A Store with a wrong WHERE clause is then
// a failed lookup rather than a membership in somebody else's space.
func (g Guard) Resolve(ctx context.Context, userID, spaceID string) (Scope, error) {
	if userID == "" {
		return Scope{}, ErrNotMember
	}
	if spaceID == "" {
		return Scope{UserID: userID, resolved: true}, nil
	}

	member, err := g.Store.Membership(ctx, spaceID, userID)
	if err != nil {
		return Scope{}, err
	}
	if member.SpaceID != spaceID || member.UserID != userID {
		return Scope{}, ErrNotMember
	}
	if !g.ladder().Valid(member.Role) {
		return Scope{}, ErrUnknownRole
	}

	return Scope{UserID: userID, SpaceID: spaceID, Role: member.Role, resolved: true}, nil
}

// Require resolves a space scope and refuses it with ErrForbidden unless the
// caller's role ranks at or above min.
//
// An empty space id is ErrNotMember here, not personal scope. Passing every
// minimum on an absent id is fail-open on empty input, and the realistic
// exploit is a gate and a use reading the id from different places:
// Require(ctx, uid, r.Header.Get("X-Space"), RoleAdmin) with no header, then a
// handler acting on the id in the body. A handler that genuinely serves both
// shapes calls Resolve, which is explicit about personal scope, and branches
// on Scope.Personal.
func (g Guard) Require(ctx context.Context, userID, spaceID string, min Role) (Scope, error) {
	ladder := g.ladder()
	if !ladder.Valid(min) {
		return Scope{}, ErrUnknownRole
	}
	if spaceID == "" {
		return Scope{}, ErrNotMember
	}

	scope, err := g.Resolve(ctx, userID, spaceID)
	if err != nil {
		return Scope{}, err
	}
	if !ladder.AtLeast(scope.Role, min) {
		return Scope{}, ErrForbidden
	}
	return scope, nil
}

// CanLeave reports whether the user may drop their own membership, as a nil
// error. It returns ErrSoleOwner when the caller holds the ladder's top rank
// and is the only member who does, because a space whose last owner walks out
// is a space nobody can administer, invite to, or delete.
//
// It never refuses an owner who has a peer: the check is the count, not the
// rank. Refusing every owner, as three apps do, makes "transfer ownership"
// the only exit from a space two people own equally.
//
// This is a read, and the deletion that follows it is a second statement, so
// the pair is time-of-check to time-of-use. Two owners leaving at the same
// instant both count two owners and both pass, and the space ends with none.
// The package cannot close that on its own without taking a database
// dependency, so the caller must: run CanLeave and the DELETE inside one
// transaction, with the space's membership rows locked for the duration
// (SELECT ... FOR UPDATE on the rows CountRole counts, or a serializable
// transaction with a retry). Calling CanLeave outside the transaction that
// deletes reproduces the bug Sablier, Agenda and Plume ship today.
//
// The argument order matches Resolve — user first, then space — deliberately
// against the original spec, which had it reversed here. Both are strings and
// nothing would catch a swap, and the two calls sit in the same handler.
func (g Guard) CanLeave(ctx context.Context, userID, spaceID string) error {
	if spaceID == "" {
		return ErrNotMember
	}

	scope, err := g.Resolve(ctx, userID, spaceID)
	if err != nil {
		return err
	}

	top := g.ladder().Top()
	if scope.Role != top {
		return nil
	}

	owners, err := g.Store.CountRole(ctx, spaceID, top)
	if err != nil {
		return err
	}
	if owners <= 1 {
		return ErrSoleOwner
	}
	return nil
}

// Spaces returns every membership the user holds, for the space switcher and
// for scoping a list query.
//
// It applies the same identity rule as Resolve to each row, because this list
// is what a switcher renders: a row whose UserID is not the argument, or that
// is missing either id, is dropped rather than returned. So is a row carrying
// a role the ladder does not rank. A Store with a bad join hands back a
// shorter list, never another user's spaces.
func (g Guard) Spaces(ctx context.Context, userID string) ([]Membership, error) {
	if userID == "" {
		return nil, ErrNotMember
	}

	all, err := g.Store.Memberships(ctx, userID)
	if err != nil {
		return nil, err
	}

	ladder := g.ladder()
	kept := make([]Membership, 0, len(all))
	for _, member := range all {
		if member.UserID == userID && member.SpaceID != "" && ladder.Valid(member.Role) {
			kept = append(kept, member)
		}
	}
	return kept, nil
}
