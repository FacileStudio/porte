package magiclinktest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

func testConcurrentConsume(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	mustCreate(t, store, link(newUser(t), "race", "", epoch))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := store.Consume(context.Background(), "race", epoch.Add(time.Minute)); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d consumes of one link succeeded, want exactly 1", wins.Load())
	}
}

func testConcurrentCreate(t *testing.T, store porte.MagicLinkStore, newUser func(*testing.T) int64) {
	user := newUser(t)
	hashes := []string{"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7"}
	var wg sync.WaitGroup
	for _, hash := range hashes {
		wg.Go(func() {
			if err := store.Create(context.Background(), link(user, hash, "", epoch)); err != nil {
				t.Errorf("create %s: %v", hash, err)
			}
		})
	}
	wg.Wait()
	live := 0
	for _, hash := range hashes {
		if _, err := store.Consume(context.Background(), hash, epoch.Add(time.Minute)); err == nil {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("%d links were live after concurrent creates, want exactly 1", live)
	}
}
