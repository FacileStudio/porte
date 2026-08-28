// Package spacestest is the conformance suite for a spaces.Store, plus an
// in-memory Store to run it against.
//
// An adopting app runs Conformance against its own Store so that it inherits
// the proof and not only the code: the invariants in spaces.Guard are only
// worth anything if the table underneath answers honestly, and a Store that
// reports absence as success, blanks the ids it returns, or lists another
// user's rows silently disarms every guard above it.
//
// The suite asserts what a Store returns, not only how much of it: ids
// populated from the row and matching what was asked for, roles preserved, and
// Memberships listing the caller's own rows and no others.
package spacestest

import (
	"context"
	"sync"

	"github.com/FacileStudio/porte/spaces"
)

// Seeder is the write half Conformance needs to build its fixture. A Store
// under test must implement it, over whatever its real insert path is; the
// suite fails the test rather than skipping when it does not, because a
// conformance run that quietly does nothing is worse than no run.
type Seeder interface {
	Seed(ctx context.Context, member spaces.Membership) error
}

// Memory is an in-memory spaces.Store. It is the reference implementation the
// package's own tests run on, and the shape an adopter's Store should behave
// like: absence is ErrNotMember, and nothing else is.
type Memory struct {
	mu      sync.RWMutex
	members []spaces.Membership
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{} }

// Seed inserts or replaces one membership.
func (m *Memory) Seed(_ context.Context, member spaces.Membership) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.members {
		if existing.SpaceID == member.SpaceID && existing.UserID == member.UserID {
			m.members[i] = member
			return nil
		}
	}
	m.members = append(m.members, member)
	return nil
}

// Membership returns the user's row in one space, or spaces.ErrNotMember.
func (m *Memory) Membership(_ context.Context, spaceID, userID string) (spaces.Membership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, member := range m.members {
		if member.SpaceID == spaceID && member.UserID == userID {
			return member, nil
		}
	}
	return spaces.Membership{}, spaces.ErrNotMember
}

// Memberships returns every space the user belongs to.
func (m *Memory) Memberships(_ context.Context, userID string) ([]spaces.Membership, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []spaces.Membership
	for _, member := range m.members {
		if member.UserID == userID {
			out = append(out, member)
		}
	}
	return out, nil
}

// CountRole returns how many members of the space hold exactly that role.
func (m *Memory) CountRole(_ context.Context, spaceID string, role spaces.Role) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, member := range m.members {
		if member.SpaceID == spaceID && member.Role == role {
			count++
		}
	}
	return count, nil
}
