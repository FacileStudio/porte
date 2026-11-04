package forfait

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// exportVersion is the only document version Import accepts.
const exportVersion = 1

// maxExport is the largest document Import reads.
const maxExport = 4 << 20

// errAlreadyApplied refuses an Import over state this process already holds,
// which is newer than anything saved before it.
var errAlreadyApplied = errors.New("forfait: import after a snapshot was applied")

// exported is the persisted shape of a Store's applied state.
type exported struct {
	Version int                                   `json:"version"`
	Applied bool                                  `json:"applied"`
	Spaces  map[string]map[string]json.RawMessage `json:"spaces"`
	People  map[string]map[string]json.RawMessage `json:"people"`
}

// Export is the applied state as a versioned JSON document, so an app does
// not fail open again after a restart. Save it, as one row or one file, after
// every Apply, and hand it to Import at boot before the first pull. It
// records whether a snapshot carrying entitlements was ever applied, so a
// Store that was still failing open exports as such.
func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	document := exported{Version: exportVersion, Applied: s.applied}
	if s.applied {
		document.Spaces = s.encodeScopes(s.spaces)
		document.People = s.encodeScopes(s.people)
	}
	return json.Marshal(document)
}

// Import restores a document Export produced. It reads at most 4 MiB, rejects
// unknown fields, trailing data and any version but the current one, and
// filters every value through the same rules as Apply: undeclared keys,
// malformed values and scopes over 200 keys read as defaults. It refuses to
// run once this Store applied a snapshot, and on any error the Store is left
// unchanged, still failing open.
func (s *Store) Import(b []byte) error {
	if len(b) > maxExport {
		return fmt.Errorf("forfait: import of %d bytes exceeds %d", len(b), maxExport)
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	var document exported
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("forfait: decode the import: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("forfait: trailing data after the import")
	}
	if document.Version != exportVersion {
		return fmt.Errorf("forfait: import version %d is not %d", document.Version, exportVersion)
	}
	spaces, people := s.indexScopes(document.Spaces), s.indexScopes(document.People)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applied {
		return errAlreadyApplied
	}
	s.spaces, s.people, s.applied = spaces, people, document.Applied
	return nil
}

// indexScopes filters every persisted scope through index.
func (s *Store) indexScopes(scopes map[string]map[string]json.RawMessage) map[string]map[string]value {
	resolved := make(map[string]map[string]value, len(scopes))
	for id, entitlements := range scopes {
		resolved[id] = index(s.features, entitlements)
	}
	return resolved
}

// encodeScopes writes every scope's values back as the JSON Apply reads.
func (s *Store) encodeScopes(scopes map[string]map[string]value) map[string]map[string]json.RawMessage {
	encoded := make(map[string]map[string]json.RawMessage, len(scopes))
	for id, values := range scopes {
		entitlements := make(map[string]json.RawMessage, len(values))
		for key, v := range values {
			entitlements[key] = encodeValue(s.features[key].Kind, v)
		}
		encoded[id] = entitlements
	}
	return encoded
}

// encodeValue is v as a JSON bool for a Bool and a JSON integer for a Limit.
func encodeValue(kind Kind, v value) json.RawMessage {
	if kind == Bool {
		return json.RawMessage(strconv.FormatBool(v.enabled))
	}
	return json.RawMessage(strconv.FormatInt(v.limit, 10))
}
