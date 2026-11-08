package mcpauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/porte/forfait"
	"github.com/FacileStudio/porte/mcpauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func plans(paid bool) *forfait.Store {
	store := forfait.NewStore(mcpauth.AIAccessFeature())
	value := json.RawMessage("false")
	if paid {
		value = json.RawMessage("true")
	}
	store.Apply(directory.Snapshot{EntitlementsRevision: 1, People: []directory.Person{
		{Subject: subject, Entitlements: map[string]json.RawMessage{mcpauth.AIAccess: value}},
	}})
	return store
}

func gated(t *testing.T, r *registre, store mcpauth.Entitlements) http.Handler {
	t.Helper()
	require := mcpauth.Require(newVerifier(t, r, identities{}), &auth.RequireBearerTokenOptions{Scopes: []string{"courrier.read"}})
	return require(mcpauth.PlanGate(store, "https://registre.example")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
}

func TestAThirdPartyClientOnAFreePlanIsPaymentRequired(t *testing.T) {
	r := newRegistre(t)
	rec := call(gated(t, r, plans(false)), r.mint(t, nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rec.Code)
	}
	var body struct {
		Error struct {
			Code       string `json:"code"`
			UpgradeURL string `json:"upgrade_url"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "payment_required" || body.Error.UpgradeURL != "https://registre.example/spaces" {
		t.Errorf("body = %+v", body.Error)
	}
}

func TestPlanGateLetsPaidAndBulleThrough(t *testing.T) {
	r := newRegistre(t)
	if rec := call(gated(t, r, plans(true)), r.mint(t, nil)); rec.Code != http.StatusNoContent {
		t.Errorf("paid third party: status = %d", rec.Code)
	}
	if rec := call(gated(t, r, plans(false)), bulleToken(t, r)); rec.Code != http.StatusNoContent {
		t.Errorf("Bulle on a free plan: status = %d", rec.Code)
	}
	if rec := call(gated(t, r, nil), bulleToken(t, r)); rec.Code != http.StatusNoContent {
		t.Errorf("Bulle with no plans: status = %d", rec.Code)
	}
}

func TestAnActorFromAnotherClientIsThirdParty(t *testing.T) {
	r := newRegistre(t)
	token := r.mint(t, map[string]any{"aud": appAudience, "client_id": "plume", "act": map[string]string{"sub": "plume"}})
	if rec := call(gated(t, r, plans(false)), token); rec.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402: only Bulle's exchange skips the plan gate", rec.Code)
	}
}

func TestPlanGateWithoutRequireIsUnauthenticated(t *testing.T) {
	rec := httptest.NewRecorder()
	mcpauth.PlanGate(plans(true), "https://registre.example")(http.NotFoundHandler()).
		ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
