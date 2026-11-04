package forfait

import (
	"log/slog"
	"sync"

	"github.com/FacileStudio/porte/directory"
)

// Store holds the entitlements of every scope from the last authoritative
// snapshot, one whose EntitlementsRevision is above 0. It is safe for concurrent use. Issuer and Logger are read on
// every call and must be set before the Store is shared.
//
// The Store lives in memory. So that a restart never fails open again, an app
// saves Export's document (one row or one file) after every Apply, and calls
// Import with it at boot, before the first pull.
type Store struct {
	// Issuer is the app's OIDC issuer. When set, every LimitError carries
	// UpgradeURL(Issuer, scope.SpaceID).
	Issuer string
	// Logger receives the one warning logged while the Store fails open.
	// Nil means slog.Default().
	Logger *slog.Logger

	features map[string]Feature
	defaults map[string]value
	warned   sync.Once

	mu       sync.RWMutex
	version  int64
	revision int64
	spaces   map[string]map[string]value
	people   map[string]map[string]value
}

// NewStore declares the features an app enforces. It never panics: a key that
// is malformed is skipped and reads as undeclared, the first of two
// declarations of one key wins, and a malformed Default denies.
func NewStore(features ...Feature) *Store {
	s := &Store{features: map[string]Feature{}, defaults: map[string]value{}}
	for _, feature := range features {
		if _, seen := s.features[feature.Key]; seen || !keyPattern.MatchString(feature.Key) {
			continue
		}
		s.features[feature.Key] = feature
		s.defaults[feature.Key], _ = decode(feature.Kind, feature.Default)
	}
	return s
}

// Apply replaces every scope's entitlements with the snapshot's. Call it from
// the app's directory.Syncer Apply.
//
// Only Snapshot.EntitlementsRevision ends the fail-open period: a snapshot
// whose revision is 0 comes from a Registre that never received a push, and
// Apply ignores it, so an app can ship before Registre serves entitlements.
// From the first revision on, every accepted snapshot is the whole truth and
// a scope it carries no value for reads the feature defaults.
//
// Apply also ignores a snapshot older than the state it holds: a lower
// EntitlementsRevision, or a lower non-zero Version. State restored by Import
// counts as applied for that comparison. Malformed values, undeclared keys and
// scopes with more than 200 keys are dropped, and the features they name read
// as their defaults.
func (s *Store) Apply(snap directory.Snapshot) {
	spaces := make(map[string]map[string]value, len(snap.Spaces))
	for _, space := range snap.Spaces {
		spaces[space.ID] = index(s.features, space.Entitlements)
	}
	people := make(map[string]map[string]value, len(snap.People))
	for _, person := range snap.People {
		people[person.Subject] = index(s.features, person.Entitlements)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.accepts(snap.Version, snap.EntitlementsRevision) {
		return
	}
	s.spaces, s.people, s.version, s.revision = spaces, people, snap.Version, snap.EntitlementsRevision
}

// accepts reports whether state at version and revision may replace what the
// Store holds. The caller holds the write lock.
func (s *Store) accepts(version, revision int64) bool {
	return revision > 0 && revision >= s.revision && (version == 0 || version >= s.version)
}

// Enabled reports whether a Bool feature is on for the scope. Before the
// first snapshot it is true. An undeclared key, or a key declared as a Limit,
// is a programmer error and answers false.
func (s *Store) Enabled(sc Scope, key string) bool {
	return s.resolve(sc, key, Bool).enabled
}

// Limit is a Limit feature's ceiling for the scope, -1 meaning unlimited.
// Before the first snapshot it is -1. An undeclared key, or a key declared as
// a Bool, is a programmer error and answers 0.
func (s *Store) Limit(sc Scope, key string) int64 {
	return s.resolve(sc, key, Limit).limit
}

// Check reports whether the scope may go from used to used+adding of a Limit
// feature. It answers nil at or under the ceiling, when the ceiling is
// unlimited, and when adding is 0, so an over-limit scope can always read and
// delete. Over the ceiling it answers a *LimitError matching ErrLimit. A
// negative used or adding answers ErrInvalidUsage. The comparison cannot
// overflow. An undeclared key has a ceiling of 0 and refuses any addition.
//
// Because adding 0 always passes, an app measuring in a coarse unit rounds
// both counts up: a 1 KiB upload against a limit in GB adds 1, not 0. Check
// and the creation it guards are not atomic, so two concurrent requests can
// both pass at the ceiling; an app that needs strictness checks again inside
// the transaction that creates the resource, against the count it locked.
func (s *Store) Check(sc Scope, key string, used, adding int64) error {
	if used < 0 || adding < 0 {
		return ErrInvalidUsage
	}
	limit := s.Limit(sc, key)
	if adding == 0 || limit == -1 || used <= limit-adding {
		return nil
	}
	refusal := &LimitError{Key: key, Limit: limit}
	if s.Issuer != "" {
		refusal.UpgradeURL = UpgradeURL(s.Issuer, sc.SpaceID)
	}
	return refusal
}

// resolve finds the value of key for sc: the scope's own value, else the
// feature default, else everything allowed before the first snapshot.
func (s *Store) resolve(sc Scope, key string, kind Kind) value {
	feature, declared := s.features[key]
	if !declared || feature.Kind != kind {
		return value{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revision == 0 {
		s.warned.Do(s.warnUnsynced)
		return value{enabled: true, limit: -1}
	}
	scope := s.spaces[sc.SpaceID]
	if sc.SpaceID == "" {
		scope = s.people[sc.Subject]
	}
	if v, ok := scope[key]; ok {
		return v
	}
	return s.defaults[key]
}

// warnUnsynced logs that the Store is allowing everything for now.
func (s *Store) warnUnsynced() {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("forfait: no entitlements snapshot applied yet, allowing every feature")
}
