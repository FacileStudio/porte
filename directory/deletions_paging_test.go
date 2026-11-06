package directory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSubjectsBeyondOnePageAreAllHandledInOnePoll(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	base := time.Now().Add(-48 * time.Hour).Truncate(time.Microsecond)
	for i := range 2500 {
		reg.delete(fmt.Sprintf("p%04d", i), base.Add(time.Duration(i)*time.Second))
	}
	d := receiver(reg, c, &memoryState{})
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.erased) != 2500 {
		t.Fatalf("callbacks = %d, want 2500", len(c.erased))
	}
	if err := d.Poll(context.Background()); err != nil || len(c.erased) != 2500 {
		t.Fatalf("second poll = %v, callbacks = %d", err, len(c.erased))
	}
}

func TestMoreThanAPageInsideTheOverlapDoesNotStall(t *testing.T) {
	reg, c, state := newRegistre(t), &calls{}, &memoryState{}
	base := time.Now().Add(-30 * time.Second).Truncate(time.Microsecond)
	for i := range 1200 {
		reg.delete(fmt.Sprintf("p%04d", i), base.Add(time.Duration(i)*time.Millisecond))
	}
	if err := receiver(reg, c, state).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	reg.delete("late", base.Add(5*time.Second))
	if err := receiver(reg, c, state).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.erased) != 1201 || c.erased[1200] != reg.server.URL+"|late" {
		t.Fatalf("callbacks = %d, want 1200 then the late one", len(c.erased))
	}
}

func TestMoreThanAPageOnOneInstantTerminatesWithAnError(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	at := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	for i := range 1500 {
		reg.delete(fmt.Sprintf("p%04d", i), at)
	}
	err := receiver(reg, c, &memoryState{}).Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "share one timestamp") {
		t.Fatalf("poll = %v, want the same-instant error", err)
	}
	if len(c.erased) != 1000 {
		t.Fatalf("callbacks = %d, want the 1000 Registre lists", len(c.erased))
	}
}

func TestOneFailingSubjectDoesNotBlockTheOthers(t *testing.T) {
	reg, c, state := newRegistre(t), &calls{fail: map[string]bool{"bob": true}}, &memoryState{}
	base := time.Now().Add(-time.Hour)
	for i, who := range []string{"alice", "bob", "carol", "dave"} {
		reg.delete(who, base.Add(time.Duration(i)*time.Minute))
	}
	for range 3 {
		if err := receiver(reg, c, state).Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "bob") {
			t.Fatalf("poll = %v, want bob's error", err)
		}
	}
	got := strings.Join(c.erased, ",")
	for _, who := range []string{"alice", "carol", "dave"} {
		if strings.Count(got, who) != 1 {
			t.Errorf("%s handled %d times: %v", who, strings.Count(got, who), c.erased)
		}
	}
	if strings.Count(got, "bob") != 3 {
		t.Errorf("bob tried %d times, want 3", strings.Count(got, "bob"))
	}
}

func TestKeyFailuresAreRetriableAndUnknownKidIsNot(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d := receiver(reg, c, nil)
	unknown := reg.notice("alice", func(h, _ map[string]any) { h["kid"] = "zz" })
	if code := push(d, unknown); code != http.StatusBadRequest {
		t.Fatalf("unknown kid after a fresh fetch = %d, want 400", code)
	}
	if code := push(d, unknown); code != http.StatusServiceUnavailable {
		t.Fatalf("unknown kid inside the refetch gap = %d, want 503", code)
	}
}

func TestDiscoveryForAnotherIssuerIsRefused(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://evil.test","jwks_uri":"` + reg.server.URL + `/keys"}`))
	}))
	t.Cleanup(other.Close)
	d := receiver(reg, c, nil)
	d.Client.Issuer = other.URL
	token := reg.notice("alice", func(_, claims map[string]any) { claims["iss"] = other.URL })
	if code := push(d, token); code != http.StatusServiceUnavailable || len(c.erased) != 0 {
		t.Fatalf("push = %d, callbacks = %v", code, c.erased)
	}
}

func TestDiscoveryRedirectIsNotFollowed(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	moved := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, reg.server.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(moved.Close)
	d := receiver(reg, c, nil)
	d.Client.Issuer = moved.URL
	token := reg.notice("alice", func(_, claims map[string]any) { claims["iss"] = moved.URL })
	if code := push(d, token); code != http.StatusServiceUnavailable {
		t.Fatalf("push = %d, want 503", code)
	}
}

func TestMissingCallbackIsAnErrorNotAPanic(t *testing.T) {
	reg := newRegistre(t)
	d := receiver(reg, &calls{}, nil)
	d.OnPersonDeleted = nil
	if err := d.Poll(context.Background()); err == nil {
		t.Fatal("poll without a callback succeeded")
	}
	if code := push(d, reg.notice("alice")); code != http.StatusInternalServerError {
		t.Fatalf("push = %d, want 500", code)
	}
}
