package forfait

import (
	"errors"
	"math"
	"testing"
)

// TestCheck walks the ceiling from both sides, unlimited, and every bound an
// int64 could wrap on.
func TestCheck(t *testing.T) {
	store := applied(map[string]string{"nuage.storage_gb": "10", "courrier.mailboxes": "-1"}, nil)
	store.Issuer = "https://registre.facile.studio/"
	cases := []struct {
		name         string
		key          string
		used, adding int64
		want         error
	}{
		{"under", "nuage.storage_gb", 3, 5, nil},
		{"at", "nuage.storage_gb", 5, 5, nil},
		{"over", "nuage.storage_gb", 6, 5, ErrLimit},
		{"already over, adding nothing", "nuage.storage_gb", 50, 0, nil},
		{"already over, adding one", "nuage.storage_gb", 50, 1, ErrLimit},
		{"huge adding", "nuage.storage_gb", 1, math.MaxInt64, ErrLimit},
		{"huge used", "nuage.storage_gb", math.MaxInt64, math.MaxInt64, ErrLimit},
		{"unlimited", "courrier.mailboxes", math.MaxInt64, math.MaxInt64, nil},
		{"negative used", "nuage.storage_gb", -100, 1, ErrInvalidUsage},
		{"negative adding", "nuage.storage_gb", 1, -1, ErrInvalidUsage},
		{"min int adding", "courrier.mailboxes", 0, math.MinInt64, ErrInvalidUsage},
		{"undeclared", "nuage.other", 0, 1, ErrLimit},
	}
	for _, c := range cases {
		err := store.Check(Scope{SpaceID: "pro"}, c.key, c.used, c.adding)
		if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
			t.Errorf("%s: Check = %v, want %v", c.name, err, c.want)
		}
	}
}

// TestTheRefusalCarriesTheUpgradeURL pins the fields apps map to a 402.
func TestTheRefusalCarriesTheUpgradeURL(t *testing.T) {
	store := applied(map[string]string{"nuage.storage_gb": "10"}, nil)
	store.Issuer = "https://registre.facile.studio/"
	var refusal *LimitError
	if !errors.As(store.Check(Scope{SpaceID: "pro"}, "nuage.storage_gb", 10, 1), &refusal) {
		t.Fatal("Check over the ceiling did not answer a *LimitError")
	}
	if refusal.Key != "nuage.storage_gb" || refusal.Limit != 10 ||
		refusal.UpgradeURL != "https://registre.facile.studio/spaces/pro" {
		t.Errorf("refusal = %+v", refusal)
	}
	if !errors.As(store.Check(Scope{Subject: "u1"}, "nuage.storage_gb", 5, 1), &refusal) ||
		refusal.UpgradeURL != "https://registre.facile.studio/spaces" {
		t.Errorf("personal refusal = %+v", refusal)
	}
	store.Issuer = ""
	if errors.As(store.Check(Scope{SpaceID: "pro"}, "nuage.storage_gb", 10, 1), &refusal) && refusal.UpgradeURL != "" {
		t.Errorf("a store with no issuer built %q", refusal.UpgradeURL)
	}
}

// TestUpgradeURL pins both shapes and that a space id cannot leave the path.
func TestUpgradeURL(t *testing.T) {
	cases := map[[2]string]string{
		{"https://r.example", "spc_1"}:  "https://r.example/spaces/spc_1",
		{"https://r.example/", ""}:      "https://r.example/spaces",
		{"https://r.example", "../a?b"}: "https://r.example/spaces/..%2Fa%3Fb",
	}
	for in, want := range cases {
		if got := UpgradeURL(in[0], in[1]); got != want {
			t.Errorf("UpgradeURL(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
