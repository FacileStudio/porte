package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// counting serves snapshots whose version rises by one per pull.
func counting(t *testing.T, pause time.Duration) (Client, *atomic.Int64) {
	t.Helper()
	var pulls atomic.Int64
	registre := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		version := pulls.Add(1)
		time.Sleep(pause)
		_ = json.NewEncoder(w).Encode(Snapshot{Version: version})
	}))
	t.Cleanup(registre.Close)
	return Client{Issuer: registre.URL}, &pulls
}

// TestOverlappingSyncsApplyInOrderOneAtATime: concurrent Sync calls never run
// Apply together, and never commit an older version after a newer one.
func TestOverlappingSyncsApplyInOrderOneAtATime(t *testing.T) {
	client, _ := counting(t, 5*time.Millisecond)
	var inside atomic.Int32
	var mu sync.Mutex
	var order []int64
	syncer := &Syncer{Client: client, Apply: func(_ context.Context, s Snapshot) error {
		if inside.Add(1) != 1 {
			t.Error("two Apply calls ran at once")
		}
		time.Sleep(time.Millisecond)
		mu.Lock()
		order = append(order, s.Version)
		mu.Unlock()
		inside.Add(-1)
		return nil
	}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = syncer.Sync(context.Background())
		}()
	}
	wg.Wait()
	for i := 1; i < len(order); i++ {
		if order[i] <= order[i-1] {
			t.Fatalf("applied out of order: %v", order)
		}
	}
}

// TestRunDebouncesABurstAndStopsOnCancel: a burst of nudges costs one pull
// after the debounce, and cancelling the context ends Run even mid-debounce.
func TestRunDebouncesABurstAndStopsOnCancel(t *testing.T) {
	client, pulls := counting(t, 0)
	syncer := &Syncer{Client: client, Interval: time.Hour, Apply: func(context.Context, Snapshot) error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(stopped)
	}()
	waitFor(t, func() bool { return pulls.Load() == 1 })
	for range 5 {
		syncer.Nudge()
	}
	waitFor(t, func() bool { return pulls.Load() == 2 })
	time.Sleep(debounce + 500*time.Millisecond)
	if got := pulls.Load(); got != 2 {
		t.Fatalf("five nudges cost %d pulls after the boot pull, want 1", got-1)
	}
	syncer.Nudge()
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop when its context ended mid-debounce")
	}
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
