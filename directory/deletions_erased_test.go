package directory

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type accounts struct {
	mu   sync.Mutex
	held map[string]bool
	fail bool
}

func (a *accounts) holds(_ context.Context, _, subject string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return false, errors.New("db is down")
	}
	return a.held[subject], nil
}

func (a *accounts) set(subject string, held bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.held[subject] = held
}

func holdingReceiver(reg *registre, c *calls, state StateStore) (*Deletions, *accounts) {
	a := &accounts{held: map[string]bool{}}
	d := receiver(reg, c, state)
	d.Holds = a.holds
	return d, a
}

func TestARecreatedAccountIsErasedAgainOnPush(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d, a := holdingReceiver(reg, c, &memoryState{})
	token := reg.notice("alice")
	push(d, token)
	a.set("alice", true)
	if code := push(d, token); code != http.StatusAccepted {
		t.Fatalf("push = %d, want 202", code)
	}
	a.set("alice", false)
	push(d, token)
	if len(c.erased) != 2 || len(c.porte) != 2 {
		t.Fatalf("callbacks = %v, porte erasures = %v, want two each", c.erased, c.porte)
	}
}

func TestARecreatedAccountIsErasedAgainOnPollAndNobodyElse(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d, a := holdingReceiver(reg, c, &memoryState{})
	now := time.Now().Truncate(time.Microsecond)
	reg.delete("bob", now.Add(-2*time.Second))
	reg.delete("alice", now.Add(-time.Second))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.set("alice", true)
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(c.erased, ",")
	if strings.Count(got, "alice") != 2 || strings.Count(got, "bob") != 1 {
		t.Fatalf("callbacks = %v, want alice twice and bob once", c.erased)
	}
}

func TestAFailedHoldsCheckRejectsThePushAndRetries(t *testing.T) {
	reg, c := newRegistre(t), &calls{}
	d, a := holdingReceiver(reg, c, &memoryState{})
	token := reg.notice("alice")
	push(d, token)
	a.set("alice", true)
	a.fail = true
	if code := push(d, token); code != http.StatusInternalServerError {
		t.Fatalf("push = %d, want 500", code)
	}
	a.fail = false
	push(d, token)
	if len(c.erased) != 2 {
		t.Fatalf("callbacks = %v, want the retry to erase again", c.erased)
	}
}

func TestErasedReadsTheSharedStateOnEveryCall(t *testing.T) {
	reg, c, state := newRegistre(t), &calls{}, &memoryState{}
	d := receiver(reg, c, state)
	other := receiver(reg, c, state)
	ctx := context.Background()
	if erased, err := other.Erased(ctx, reg.server.URL, "alice"); err != nil || erased {
		t.Fatalf("before the notice: erased = %v, %v", erased, err)
	}
	push(d, reg.notice("alice"))
	cases := map[string]bool{
		reg.server.URL + "|alice":  true,
		reg.server.URL + "/|alice": true,
		reg.server.URL + "|bob":    false,
		"https://other.test|alice": false,
		reg.server.URL + "|":       false,
	}
	for in, want := range cases {
		provider, subject, _ := strings.Cut(in, "|")
		if erased, err := other.Erased(ctx, provider, subject); err != nil || erased != want {
			t.Errorf("Erased(%q, %q) = %v, %v, want %v", provider, subject, erased, err, want)
		}
	}
	if erased, _ := receiver(reg, c, nil).Erased(ctx, reg.server.URL, "alice"); erased {
		t.Fatal("a receiver without State answered erased")
	}
}
