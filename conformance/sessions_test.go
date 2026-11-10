package conformance

import (
	"context"
	"sync"
	"time"

	"github.com/FacileStudio/porte"
)

type sessions struct {
	mu   sync.Mutex
	rows map[string]porte.Session
	next int64
}

func newSessions() *sessions { return &sessions{rows: map[string]porte.Session{}} }

func (s *sessions) Create(_ context.Context, session porte.Session) (porte.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	session.ID = s.next
	s.rows[session.TokenHash] = session
	return session, nil
}

func (s *sessions) Find(_ context.Context, tokenHash string) (porte.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.rows[tokenHash]
	if !ok {
		return porte.Session{}, porte.ErrNotFound
	}
	return session, nil
}

func (s *sessions) Touch(_ context.Context, tokenHash string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.rows[tokenHash]
	session.LastUsedAt = at
	s.rows[tokenHash] = session
	return nil
}

func (s *sessions) Delete(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, tokenHash)
	return nil
}

func (s *sessions) DeleteByUser(_ context.Context, userID int64) (int64, error) {
	return s.deleteWhere(func(session porte.Session) bool { return session.UserID == userID }), nil
}

func (s *sessions) DeleteLogins(_ context.Context, userID, except int64) (int64, error) {
	return s.deleteWhere(func(session porte.Session) bool {
		return session.UserID == userID && session.ID != except && !session.IsAPIToken()
	}), nil
}

func (s *sessions) deleteWhere(match func(porte.Session) bool) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted int64
	for hash, session := range s.rows {
		if match(session) {
			delete(s.rows, hash)
			deleted++
		}
	}
	return deleted
}
