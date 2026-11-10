// Package conformance pins what porte does today in JSON vectors that a port
// to another language reads. Each test builds its vector from the real
// packages and compares it with the committed file; `go test ./conformance
// -update` rewrites the files.
package conformance

import (
	"bytes"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const source = "github.com/FacileStudio/porte@deed682"

var update = flag.Bool("update", false, "rewrite the vector files from the real packages")

type testCase struct {
	Name  string `json:"name"`
	Input any    `json:"input"`
	Want  any    `json:"want"`
}

type envelope struct {
	Source   string     `json:"source"`
	Subject  string     `json:"subject"`
	Fixtures any        `json:"fixtures,omitempty"`
	Cases    []testCase `json:"cases"`
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("encoding the vector: %v", err)
	}
	return buffer.Bytes()
}

func pin(t *testing.T, subject string, fixtures any, cases []testCase) {
	t.Helper()
	got := encode(t, envelope{Source: source, Subject: subject, Fixtures: fixtures, Cases: cases})
	path := filepath.Join("vectors", subject+".json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v (run go test ./conformance -update)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s no longer matches what porte does; review the change, then run go test ./conformance -update", path)
	}
}

func requireFailing(t *testing.T, cases []testCase, failed func(testCase) bool) {
	t.Helper()
	for _, c := range cases {
		if failed(c) {
			return
		}
	}
	t.Errorf("a vector needs at least one failing-input case")
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
