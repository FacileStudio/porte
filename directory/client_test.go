package directory

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serve answers every request with status and body.
func serve(t *testing.T, status int, body string) Client {
	t.Helper()
	registre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(registre.Close)
	return Client{Issuer: registre.URL}
}

// TestFailuresAreTyped: a non-200 and a malformed body are ErrUnavailable,
// worth a retry; a body over the cap is ErrSnapshotTooLarge, which is not.
func TestFailuresAreTyped(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"forbidden", http.StatusForbidden, `{"error":"no"}`, ErrUnavailable},
		{"server error", http.StatusBadGateway, ``, ErrUnavailable},
		{"malformed", http.StatusOK, `{"version":`, ErrUnavailable},
		{"oversized", http.StatusOK, `{"version":1,"spaces":[],"x":"` + strings.Repeat("a", MaxSnapshotBytes) + `"}`, ErrSnapshotTooLarge},
	}
	for _, c := range cases {
		_, err := serve(t, c.status, c.body).Snapshot(context.Background())
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if errors.Is(c.want, ErrSnapshotTooLarge) && errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: an oversized snapshot also reads as unavailable", c.name)
		}
	}
}

// TestASnapshotAtTheCapDecodes: exactly MaxSnapshotBytes is not oversized.
func TestASnapshotAtTheCapDecodes(t *testing.T) {
	prefix, suffix := `{"version":7,"spaces":[],"x":"`, `"}`
	body := prefix + strings.Repeat("a", MaxSnapshotBytes-len(prefix)-len(suffix)) + suffix
	snapshot, err := serve(t, http.StatusOK, body).Snapshot(context.Background())
	if err != nil || snapshot.Version != 7 {
		t.Fatalf("a snapshot of exactly the cap = %+v, %v", snapshot.Version, err)
	}
}
