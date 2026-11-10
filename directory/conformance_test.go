package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

const vectorPath = "../conformance/vectors/directory_snapshot.json"

var update = flag.Bool("update", false, "rewrite ../conformance/vectors/directory_snapshot.json")

type snapshotInput struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	PadTo  int    `json:"pad_to,omitempty"`
}

type canned struct {
	in   snapshotInput
	seen *http.Request
}

func (c *canned) RoundTrip(r *http.Request) (*http.Response, error) {
	c.seen = r
	body := c.in.Body
	if c.in.PadTo > len(body) {
		body += strings.Repeat(" ", c.in.PadTo-len(body))
	}
	return &http.Response{StatusCode: c.in.Status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}

func snapshotView(s Snapshot) map[string]any {
	spaces := []map[string]any{}
	for _, space := range s.Spaces {
		members := []Member{}
		members = append(members, space.Members...)
		spaces = append(spaces, map[string]any{
			"id": space.ID, "name": space.Name, "members": members, "entitlements": rawMap(space.Entitlements),
		})
	}
	people := []map[string]any{}
	for _, person := range s.People {
		people = append(people, map[string]any{"sub": person.Subject, "entitlements": rawMap(person.Entitlements)})
	}
	return map[string]any{
		"version": s.Version, "entitlements_revision": s.EntitlementsRevision, "spaces": spaces, "people": people,
	}
}

func rawMap(entitlements map[string]json.RawMessage) map[string]string {
	view := map[string]string{}
	for key, value := range entitlements {
		view[key] = string(value)
	}
	return view
}

func snapshotWant(in snapshotInput) map[string]any {
	transport := &canned{in: in}
	client := Client{Issuer: "https://sso.test/", ClientID: "app-client", ClientSecret: "app-secret", HTTP: &http.Client{Transport: transport}}
	snapshot, err := client.Snapshot(context.Background())
	want := map[string]any{"error": nil, "snapshot": nil}
	switch {
	case errors.Is(err, ErrSnapshotTooLarge):
		want["error"] = "too_large"
	case errors.Is(err, ErrUnavailable):
		want["error"] = "unavailable"
	case err != nil:
		want["error"] = err.Error()
	default:
		want["snapshot"] = snapshotView(snapshot)
	}
	user, password, _ := transport.seen.BasicAuth()
	want["request"] = map[string]string{
		"method": transport.seen.Method, "url": transport.seen.URL.String(),
		"basic_user": user, "basic_password": password, "content_type": transport.seen.Header.Get("Content-Type"),
	}
	return want
}

func TestDirectorySnapshotVector(t *testing.T) {
	type testCase struct {
		Name  string         `json:"name"`
		Input snapshotInput  `json:"input"`
		Want  map[string]any `json:"want"`
	}
	var cases []testCase
	for _, c := range snapshotInputs() {
		cases = append(cases, testCase{Name: c.name, Input: c.in, Want: snapshotWant(c.in)})
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"source": "github.com/FacileStudio/porte/directory@v0.3.0", "subject": "directory_snapshot",
		"fixtures": map[string]any{"max_snapshot_bytes": MaxSnapshotBytes, "path": "/api/directory/snapshot"},
		"cases":    cases,
	}); err != nil {
		t.Fatalf("encoding the vector: %v", err)
	}
	compareVector(t, buffer.Bytes())
}

func compareVector(t *testing.T, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(vectorPath, got, 0o644); err != nil {
			t.Fatalf("writing %s: %v", vectorPath, err)
		}
		return
	}
	want, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("reading %s: %v (run go test -run DirectorySnapshotVector -update)", vectorPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s no longer matches what directory does; review, then run go test -run DirectorySnapshotVector -update", vectorPath)
	}
}
