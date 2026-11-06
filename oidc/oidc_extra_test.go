package oidc

import (
	"encoding/json"
	"testing"
)

func TestExtraClaimsKeepsOnlyNamedKeys(t *testing.T) {
	token := `{"sub":"u1","email":"a@b.c","connections":{"discord":"42"},"secret":"nope"}`
	decode := func(into any) error { return json.Unmarshal([]byte(token), into) }

	extra, err := extraClaims([]string{"connections", "missing"}, decode)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) != 1 || string(extra["connections"]) != `{"discord":"42"}` {
		t.Fatalf("extra = %v, want only connections", extra)
	}

	none, err := extraClaims(nil, decode)
	if err != nil || none != nil {
		t.Fatalf("no names must yield no map, got %v %v", none, err)
	}
}
