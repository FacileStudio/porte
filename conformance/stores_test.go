package conformance

import (
	"context"
	"time"

	"github.com/FacileStudio/porte"
)

func (s *sessions) ListByUser(_ context.Context, userID int64) ([]porte.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var listed []porte.Session
	for _, session := range s.rows {
		if session.UserID == userID {
			listed = append(listed, session)
		}
	}
	return listed, nil
}

func (s *sessions) DeleteByID(_ context.Context, userID, sessionID int64) error {
	s.deleteWhere(func(session porte.Session) bool { return session.UserID == userID && session.ID == sessionID })
	return nil
}

func (s *sessions) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	return s.deleteWhere(func(session porte.Session) bool { return session.Expired(now) }), nil
}

func (s *sessions) count(userID int64) int {
	listed, _ := s.ListByUser(context.Background(), userID)
	return len(listed)
}

type identities map[string]porte.StoredIdentity

func (i identities) Find(_ context.Context, provider, subject string) (porte.StoredIdentity, error) {
	stored, ok := i[provider+"|"+subject]
	if !ok {
		return porte.StoredIdentity{}, porte.ErrNotFound
	}
	return stored, nil
}

func (i identities) Save(_ context.Context, identity porte.StoredIdentity) error {
	i[identity.Provider+"|"+identity.Subject] = identity
	return nil
}

func (i identities) MarkRolesSynced(context.Context, string, string, time.Time) error { return nil }

func (i identities) ListByUser(context.Context, int64) ([]porte.StoredIdentity, error) {
	return nil, nil
}
