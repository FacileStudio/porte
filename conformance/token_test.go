package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/pg"
)

var tokenAlphabet = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func TestTokenVector(t *testing.T) {
	var cases []testCase
	for _, c := range [][2]string{
		{"empty", ""}, {"ascii", "abc"}, {"session shaped", "dGhpcyBpcyBhIHNlc3Npb24gdG9rZW4gZm9yIHRlc3Rz"}, {"utf8", "é"},
	} {
		name, token := c[0], c[1]
		cases = append(cases, testCase{
			Name:  "hash " + name,
			Input: map[string]string{"kind": "hash", "token": token},
			Want:  map[string]string{"hash": porte.HashToken(token)},
		})
	}
	minted := make([]string, 64)
	for i := range minted {
		token, err := porte.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if len(token) != 43 || !tokenAlphabet.MatchString(token) {
			t.Fatalf("NewToken returned %q, outside the pinned shape", token)
		}
		minted[i] = token
	}
	cases = append(cases, testCase{
		Name:  "new_token shape",
		Input: map[string]string{"kind": "new_token"},
		Want:  map[string]any{"token_length": 43, "decoded_bytes": 32, "alphabet": tokenAlphabet.String(), "padding": false},
	})
	cases = append(cases, browserTokenCase(t))
	cases = append(cases, compareCases()...)
	pin(t, "token", nil, cases)
}

func browserTokenCase(t *testing.T) testCase {
	t.Helper()
	browser, err := porte.NewBrowserToken()
	if err != nil {
		t.Fatalf("NewBrowserToken: %v", err)
	}
	if len(browser) != 45 || browser[:2] != porte.BrowserTokenPrefix || !tokenAlphabet.MatchString(browser) {
		t.Fatalf("NewBrowserToken returned %q, outside the pinned shape", browser)
	}
	return testCase{
		Name:  "new_browser_token shape",
		Input: map[string]string{"kind": "new_browser_token"},
		Want:  map[string]any{"prefix": porte.BrowserTokenPrefix, "token_length": 45, "decoded_bytes_after_prefix": 32, "alphabet": tokenAlphabet.String(), "padding": false},
	}
}

func compareCases() []testCase {
	pairs := [][3]string{
		{"equal", "same", "same"}, {"case differs", "same", "Same"}, {"prefix", "short", "shorter"},
		{"both empty", "", ""}, {"one empty", "a", ""},
	}
	cases := make([]testCase, 0, len(pairs))
	for _, pair := range pairs {
		cases = append(cases, testCase{
			Name:  "compare " + pair[0],
			Input: map[string]string{"kind": "compare", "a": pair[1], "b": pair[2]},
			Want:  map[string]bool{"equal": porte.SecureCompare(pair[1], pair[2])},
		})
	}
	return cases
}

func TestSchemaVector(t *testing.T) {
	sum := sha256.Sum256([]byte(pg.Schema))
	tampered := pg.Schema[:len(pg.Schema)-1]
	tamperedSum := sha256.Sum256([]byte(tampered))
	pin(t, "schema", nil, []testCase{
		{Name: "pg.Schema", Input: map[string]string{}, Want: map[string]string{
			"sha256": hex.EncodeToString(sum[:]), "sql": pg.Schema,
		}},
		{Name: "one byte short does not match", Input: map[string]string{"sql": tampered}, Want: map[string]any{
			"sha256": hex.EncodeToString(tamperedSum[:]), "matches": false,
		}},
	})
}
