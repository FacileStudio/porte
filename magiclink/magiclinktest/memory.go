// Package magiclinktest is the conformance suite for a porte.MagicLinkStore,
// plus an in-memory store to run it against.
//
// An adopting app runs Conformance against its own store so that it inherits
// the proof and not only the code: single use, supersession and the rate
// counts are only worth anything if the table underneath settles a race the
// way the contract says.
package magiclinktest

import (
	"context"
	"sync"
	"time"

	"github.com/FacileStudio/porte"
)

type row struct {
	link       porte.MagicLink
	consumedAt time.Time
}

// Memory is an in-memory porte.MagicLinkStore. Its mutex stands in for the
// database's atomic conditional update, which is what makes it a fair reference
// for the concurrency cases.
type Memory struct {
	mu   sync.Mutex
	rows []*row
}

// NewMemory returns an empty store.
func NewMemory() *Memory { return &Memory{} }

var _ porte.MagicLinkStore = (*Memory)(nil)

// Create stores the link and ends the user's older unconsumed links.
func (m *Memory) Create(_ context.Context, link porte.MagicLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.rows {
		if existing.link.UserID == link.UserID && existing.consumedAt.IsZero() {
			existing.consumedAt = link.CreatedAt
		}
	}
	m.rows = append(m.rows, &row{link: link})
	return nil
}

// Consume spends the link if it is unconsumed and unexpired at now.
func (m *Memory) Consume(_ context.Context, tokenHash string, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.rows {
		if existing.link.TokenHash == tokenHash && existing.consumedAt.IsZero() && existing.link.ExpiresAt.After(now) {
			existing.consumedAt = now
			return existing.link.UserID, nil
		}
	}
	return 0, porte.ErrNotFound
}

// CountSince counts the links matching key created at or after since.
func (m *Memory) CountSince(_ context.Context, key porte.LinkKey, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key.UserID == 0 && key.IP == "" {
		return 0, nil
	}
	count := 0
	for _, existing := range m.rows {
		matches := (key.UserID == 0 || existing.link.UserID == key.UserID) &&
			(key.IP == "" || existing.link.IP == key.IP)
		if matches && !existing.link.CreatedAt.Before(since) {
			count++
		}
	}
	return count, nil
}

// DeleteExpired removes links that expired before cutoff.
func (m *Memory) DeleteExpired(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.rows[:0]
	var removed int64
	for _, existing := range m.rows {
		if existing.link.ExpiresAt.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, existing)
	}
	m.rows = kept
	return removed, nil
}
