package directory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReplayedNoticeReachesTheCallbackOnce(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d := receiver(reg, c, &memoryState{})
	token := reg.notice("alice")
	for range 2 {
		if code := push(d, token); code != http.StatusAccepted {
			t.Fatalf("push = %d, want 202", code)
		}
	}
	if len(c.erased) != 1 || c.erased[0] != reg.server.URL+"|alice" || len(c.porte) != 1 {
		t.Fatalf("callbacks = %v, porte erasures = %v", c.erased, c.porte)
	}
}

func TestPushThenPollDoesNotRepeat(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d := receiver(reg, c, &memoryState{})
	push(d, reg.notice("alice"))
	reg.delete("alice", time.Now().Add(-time.Second))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.erased) != 1 {
		t.Fatalf("callbacks = %v, want one", c.erased)
	}
}

func TestCursorSurvivesARestart(t *testing.T) {
	reg, c, state := newRegistre(t), &calls{}, &memoryState{}
	first := time.Now().Add(-2 * time.Hour).Truncate(time.Microsecond)
	reg.delete("alice", first)
	reg.delete("bob", first.Add(time.Hour))
	if err := receiver(reg, c, state).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted := receiver(reg, c, state)
	reg.delete("carol", first.Add(90*time.Minute))
	if err := restarted.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.erased, ","); strings.Count(got, "alice") != 1 || strings.Count(got, "bob") != 1 ||
		strings.Count(got, "carol") != 1 {
		t.Fatalf("callbacks = %v, want each person once", c.erased)
	}
	if last := reg.sinces[len(reg.sinces)-1]; last.Before(first.Add(time.Hour).Add(-2*overlap)) || last.Before(first) {
		t.Fatalf("restart polled from %v, want the saved cursor", last)
	}
}

func TestFailedCallbackKeepsTheCursorAndRetries(t *testing.T) {
	reg, c, state := newRegistre(t), &calls{fail: map[string]bool{"bob": true}}, &memoryState{}
	base := time.Now().Add(-time.Hour)
	reg.delete("alice", base)
	reg.delete("bob", base.Add(time.Minute))
	reg.delete("carol", base.Add(2*time.Minute))
	d := receiver(reg, c, state)
	if err := d.Poll(context.Background()); err == nil {
		t.Fatal("poll succeeded though the callback failed")
	}
	if len(c.porte) != 2 {
		t.Fatalf("porte erased %v, want alice and carol despite bob failing", c.porte)
	}
	c.fail["bob"] = false
	if err := receiver(reg, c, state).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.erased, ","); strings.Count(got, "bob") != 2 || strings.Count(got, "alice") != 1 ||
		strings.Count(got, "carol") != 1 {
		t.Fatalf("callbacks = %v", c.erased)
	}
}

func TestFailedPorteErasureRetriesAndRejectsThePush(t *testing.T) {
	reg, c := newRegistre(t), &calls{failEra: true}
	d := receiver(reg, c, &memoryState{})
	token := reg.notice("alice")
	if code := push(d, token); code != http.StatusInternalServerError {
		t.Fatalf("push = %d, want 500 so Registre retries", code)
	}
	c.failEra = false
	if code := push(d, token); code != http.StatusAccepted || len(c.porte) != 1 {
		t.Fatalf("retry = %d, porte = %v", code, c.porte)
	}
}

func TestBadNoticesAreRejected(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d := receiver(reg, c, &memoryState{})
	good := reg.notice("alice")
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := &registre{t: t, key: other, server: reg.server}
	cases := badNotices(reg, forged, good)
	for name, token := range cases {
		if code := push(d, token); code != http.StatusBadRequest {
			t.Errorf("%s: push = %d, want 400", name, code)
		}
	}
	if len(c.erased) != 0 {
		t.Fatalf("callbacks = %v, want none", c.erased)
	}
	if code := push(d, good); code != http.StatusAccepted {
		t.Fatalf("good notice = %d", code)
	}
}

func badNotices(reg, forged *registre, good string) map[string]string {
	parts := strings.Split(good, ".")
	return map[string]string{
		"tampered payload": parts[0] + "." + strings.Split(reg.notice("mallory"), ".")[1] + "." + parts[2],
		"foreign key":      forged.notice("alice"),
		"wrong typ":        reg.notice("alice", func(h, _ map[string]any) { h["typ"] = "JWT" }),
		"alg none":         reg.notice("alice", func(h, _ map[string]any) { h["alg"] = "none" }),
		"wrong issuer":     reg.notice("alice", func(_, c map[string]any) { c["iss"] = "https://evil.test" }),
		"wrong audience":   reg.notice("alice", func(_, c map[string]any) { c["aud"] = []string{"other"} }),
		"expired": reg.notice("alice", func(_, c map[string]any) {
			c["iat"] = time.Now().Add(-time.Hour).Unix()
			c["exp"] = time.Now().Add(-10 * time.Minute).Unix()
		}),
		"future":   reg.notice("alice", func(_, c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }),
		"no event": reg.notice("alice", func(_, c map[string]any) { c["events"] = map[string]any{} }),
		"garbage":  "not.a.jwt",
		"empty":    "",
	}
}

func TestPushRejectsOtherMethods(t *testing.T) {
	reg := newRegistre(t)
	d := receiver(reg, &calls{}, nil)
	recorder := httptest.NewRecorder()
	d.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, DeletionsPath, nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET = %d", recorder.Code)
	}
}
