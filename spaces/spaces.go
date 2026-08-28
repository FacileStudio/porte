// Package spaces is the suite's space-membership authorization: who is in a
// space, with what role, and whether a caller may act there.
//
// Seven Go apps rederived this guard and three got it wrong, so the package
// owns only the part where drift is a security bug. There is no CRUD, no
// invitation flow, no HTTP route and no ORM here: an app keeps its own tables,
// handlers and wire shapes, and implements Store over them. What it inherits
// is the rules in Guard, and the spacestest suite that proves its own Store
// still obeys them.
//
// Standard library only, on purpose. A package every app's authorization
// depends on must not drag an ORM or a router into every binary.
package spaces

// Role is a member's rank inside one space. The suite's three are declared
// below; an app is free to name others, because a Ladder is what gives a role
// meaning here, not this list.
type Role string

// The suite's three roles, ordered by privilege in Default.
const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Membership is one row of the app's own membership table, reduced to the
// three columns authorization needs. The app's table is free to carry
// anything else it likes.
//
// All three fields are required. A Store that leaves SpaceID or UserID empty
// disarms the cross-check in Guard.Resolve, so Resolve refuses such a row as
// ErrNotMember and Guard.Spaces drops it.
type Membership struct {
	SpaceID string
	UserID  string
	Role    Role
}

// Scope is the resolved answer to "what may this request touch". Only Guard
// produces one, and only after membership has been established, so a Scope
// that reports Resolved is proof: of membership in SpaceID when it carries
// one, of nothing beyond the caller's identity when it does not.
//
// The fields are exported because middleware and handlers read them. That
// makes a Scope literal compile anywhere, which is why every method here is
// false on a value Guard did not build: a hand-written
// Scope{UserID: "mallory", SpaceID: "victim", Role: RoleOwner} is inert, and
// Guard.AssignableBy refuses it.
//
// An empty SpaceID on a resolved Scope means personal scope: the caller's own
// data, outside every space. Personal scope carries no role, because there is
// nobody else in it.
type Scope struct {
	UserID   string
	SpaceID  string
	Role     Role
	resolved bool
}

// Resolved reports whether Guard produced this Scope. It is false for the zero
// Scope and for any Scope built by hand, so a caller that ignores an error and
// carries the zero value forward holds nothing usable.
func (s Scope) Resolved() bool { return s.resolved }

// Personal reports whether the scope is the caller's own data rather than a
// space. It is false for an unresolved Scope, so ignoring an error and
// branching on Personal does not run the personal-data path for user "".
func (s Scope) Personal() bool { return s.resolved && s.SpaceID == "" }
