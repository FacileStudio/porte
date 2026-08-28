package spaces

import "context"

// Store is the app's own membership table, read-only and reduced to the three
// questions authorization asks of it. The app owns the schema, the column
// names, the id types and the migrations; it converts to Membership at the
// boundary.
//
// Membership must return ErrNotMember when there is no row, never a zero
// Membership and a nil error. A Store that reports absence as success turns
// every guard above it into a no-op, which is the exact bug this package
// exists to stop, so spacestest.Conformance checks it first.
//
// Every Membership a Store returns must carry all three fields, populated from
// the row and not from the arguments. Guard cross-checks the ids against what
// was asked for, so a Store that scans only the role column — the shape
// `SELECT role FROM ... WHERE space_id=$1 AND user_id=$2` produces — has its
// rows refused rather than trusted. Select the ids too.
//
// Role comparison here is byte-exact: this package matches the string against
// the Ladder and does no case folding, trimming or aliasing. A store whose
// column holds "Owner", " owner" or a legacy spelling must normalize at the
// boundary, because an unrecognised value is ErrUnknownRole, never a weak role.
type Store interface {
	// Membership returns the caller's row in one space, or ErrNotMember.
	Membership(ctx context.Context, spaceID, userID string) (Membership, error)

	// Memberships returns every space the user belongs to, and only that
	// user's rows. An empty result is not an error.
	Memberships(ctx context.Context, userID string) ([]Membership, error)

	// CountRole returns how many members of the space hold exactly that role.
	CountRole(ctx context.Context, spaceID string, role Role) (int, error)
}
