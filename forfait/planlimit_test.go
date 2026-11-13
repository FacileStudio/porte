package forfait

import (
	"errors"
	"fmt"
	"testing"
)

func TestARefusalNamesItsPlanLimit(t *testing.T) {
	var refusal interface{ PlanLimit() (string, string) }
	err := fmt.Errorf("creating: %w", &LimitError{Key: "nuage.storage_gb", Limit: 10, UpgradeURL: "https://sso.test/spaces"})
	if !errors.As(err, &refusal) {
		t.Fatal("a wrapped LimitError does not expose PlanLimit")
	}
	if key, url := refusal.PlanLimit(); key != "nuage.storage_gb" || url != "https://sso.test/spaces" {
		t.Fatalf("PlanLimit() = %q, %q", key, url)
	}
}
