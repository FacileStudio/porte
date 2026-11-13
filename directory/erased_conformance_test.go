package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
)

const erasedVectorPath = "../conformance/vectors/directory_erased.json"

type erasedInput struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	NoState  bool   `json:"no_state,omitempty"`
}

type holdsInput struct {
	Holds string `json:"holds"`
}

type vectorCase struct {
	Name  string         `json:"name"`
	Input any            `json:"input"`
	Want  map[string]any `json:"want"`
}

func erasedInputs() map[string]erasedInput {
	return map[string]erasedInput{
		"the handled subject at the issuer":          {"<issuer>", "alice", false},
		"the issuer with one trailing slash":         {"<issuer>/", "alice", false},
		"a subject never handled":                    {"<issuer>", "bob", false},
		"the handled subject at another provider":    {"https://other.test", "alice", false},
		"an empty subject":                           {"<issuer>", "", false},
		"a receiver without State never says erased": {"<issuer>", "alice", true},
	}
}

func erasedWant(t *testing.T, in erasedInput) map[string]any {
	t.Helper()
	reg, c, state := newRegistre(t), &calls{}, &memoryState{}
	push(receiver(reg, c, state), reg.notice("alice"))
	asked := receiver(reg, c, state)
	if in.NoState {
		asked.State = nil
	}
	provider := in.Provider
	if rest, ok := strings.CutPrefix(provider, "<issuer>"); ok {
		provider = reg.server.URL + rest
	}
	erased, err := asked.Erased(context.Background(), provider, in.Subject)
	if err != nil {
		t.Fatalf("Erased: %v", err)
	}
	return map[string]any{"erased": erased}
}

func holdsWant(t *testing.T, in holdsInput) map[string]any {
	t.Helper()
	reg, c := newRegistre(t), &calls{}
	d, a := holdingReceiver(reg, c, &memoryState{})
	token := reg.notice("alice")
	push(d, token)
	a.set("alice", in.Holds == "yes")
	a.fail = in.Holds == "fails"
	status := push(d, token)
	return map[string]any{"status": status, "callbacks": len(c.erased), "porte_erasures": len(c.porte)}
}

func TestDirectoryErasedVector(t *testing.T) {
	var cases []vectorCase
	erased := erasedInputs()
	for _, name := range slices.Sorted(maps.Keys(erased)) {
		cases = append(cases, vectorCase{Name: name, Input: erased[name], Want: erasedWant(t, erased[name])})
	}
	holds := map[string]holdsInput{
		"a redelivered notice whose subject holds no account is skipped": {"no"},
		"a redelivered notice whose subject holds an account again":      {"yes"},
		"a redelivered notice whose holds check fails is retried":        {"fails"},
	}
	for _, name := range slices.Sorted(maps.Keys(holds)) {
		cases = append(cases, vectorCase{Name: name, Input: holds[name], Want: holdsWant(t, holds[name])})
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"source": "github.com/FacileStudio/porte/directory@v0.5.0", "subject": "directory_erased",
		"fixtures": map[string]any{
			"handled": "alice, by one pushed notice before each case",
			"issuer":  "<issuer> is Client.Issuer",
			"counts":  "callbacks and porte_erasures count both deliveries of the notice",
		},
		"cases": cases,
	}); err != nil {
		t.Fatalf("encoding the vector: %v", err)
	}
	compareVector(t, erasedVectorPath, buffer.Bytes())
}
