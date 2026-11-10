package directory

import "net/http"

type namedSnapshot struct {
	name string
	in   snapshotInput
}

const fullSnapshot = `{"version":42,"entitlements_revision":7,` +
	`"spaces":[{"id":"sp_1","name":"Studio","members":[` +
	`{"sub":"u1","email":"a@example.test","name":"Ann","picture":"https://sso.test/a.png","role":"owner"},` +
	`{"sub":"u2","email":"b@example.test","name":"Bob","picture":"","role":"member"}],` +
	`"entitlements":{"ai.access":true,"storage.bytes":1073741824}}],` +
	`"people":[{"sub":"u1","entitlements":{"ai.access":{"until":"2027-01-01"}}}]}`

func snapshotInputs() []namedSnapshot {
	ok := http.StatusOK
	return []namedSnapshot{
		{"full snapshot", snapshotInput{Status: ok, Body: fullSnapshot}},
		{"unknown fields are ignored", snapshotInput{Status: ok, Body: `{"version":1,"future":true,` +
			`"spaces":[{"id":"s","name":"n","color":"red","members":[{"sub":"u","role":"admin","mfa":true}]}],` +
			`"people":[{"sub":"u","tier":"pro"}]}`}},
		{"only a version", snapshotInput{Status: ok, Body: `{"version":3}`}},
		{"null spaces and people", snapshotInput{Status: ok, Body: `{"version":3,"spaces":null,"people":null}`}},
		{"a member missing fields", snapshotInput{Status: ok, Body: `{"version":1,"spaces":[{"id":"s","members":[{"sub":"u"}]}]}`}},
		{"field names match case-insensitively", snapshotInput{Status: ok, Body: `{"Version":5,"SPACES":[{"ID":"s","Name":"n"}]}`}},
		{"a duplicate key keeps the last", snapshotInput{Status: ok, Body: `{"version":1,"version":2}`}},
		{"empty object", snapshotInput{Status: ok, Body: `{}`}},
		{"exactly the cap decodes", snapshotInput{Status: ok, Body: `{"version":9,"spaces":[]}`, PadTo: MaxSnapshotBytes}},
		{"one byte over the cap", snapshotInput{Status: ok, Body: `{"version":9,"spaces":[]}`, PadTo: MaxSnapshotBytes + 1}},
		{"malformed JSON", snapshotInput{Status: ok, Body: `{"version":`}},
		{"empty body", snapshotInput{Status: ok, Body: ``}},
		{"version as a string", snapshotInput{Status: ok, Body: `{"version":"42","spaces":[]}`}},
		{"version as a float", snapshotInput{Status: ok, Body: `{"version":4.5}`}},
		{"members not an array", snapshotInput{Status: ok, Body: `{"version":1,"spaces":[{"id":"s","members":{}}]}`}},
		{"trailing data", snapshotInput{Status: ok, Body: `{"version":1} {"version":2}`}},
		{"top level array", snapshotInput{Status: ok, Body: `[]`}},
		{"registre unavailable", snapshotInput{Status: http.StatusServiceUnavailable, Body: `{"error":{}}`}},
		{"registre refuses the client", snapshotInput{Status: http.StatusUnauthorized, Body: fullSnapshot}},
	}
}
