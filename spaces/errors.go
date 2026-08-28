package spaces

import "errors"

// The refusals this package can return. They are sentinels rather than typed
// errors because the only thing a caller does with them is map to a status
// code, and every adopter already has its own error envelope to map into.
//
// Map them, do not compare strings: ErrNotMember and ErrForbidden are both
// 403 in most apps, and an app that wants to hide a space's existence answers
// 404 to ErrNotMember without this package having an opinion.
var (
	// ErrNotMember means the user has no membership row in that space. It is
	// also what a Store returns for a lookup that found nothing, what Guard
	// returns for a row whose ids are missing or disagree with the request,
	// and what Guard.Require returns for an empty space id.
	ErrNotMember = errors.New("spaces: not a member of this space")

	// ErrForbidden means the user is a member, but ranks below the minimum
	// the operation requires.
	ErrForbidden = errors.New("spaces: insufficient role in this space")

	// ErrSoleOwner means the operation would leave the space with no member
	// at the ladder's top rank, i.e. nobody who can administer it.
	ErrSoleOwner = errors.New("spaces: the space would be left without an owner")

	// ErrUnknownRole means a role is not one the ladder ranks — a minimum the
	// caller asked for, or a value the Store returned. Either way it is a bug
	// or a corrupt row, never a permission.
	ErrUnknownRole = errors.New("spaces: unknown role")
)
