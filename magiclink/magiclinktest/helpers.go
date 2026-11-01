package magiclinktest

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
)

var epoch = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

const ttl = 15 * time.Minute

func link(userID int64, hash, ip string, created time.Time) porte.MagicLink {
	return porte.MagicLink{TokenHash: hash, UserID: userID, CreatedAt: created, ExpiresAt: created.Add(ttl), IP: ip}
}

func mustCreate(t *testing.T, store porte.MagicLinkStore, l porte.MagicLink) {
	t.Helper()
	if err := store.Create(context.Background(), l); err != nil {
		t.Fatalf("create %s: %v", l.TokenHash, err)
	}
}

func wantDead(t *testing.T, store porte.MagicLinkStore, hash string, now time.Time) {
	t.Helper()
	if _, err := store.Consume(context.Background(), hash, now); !stderrors.Is(err, porte.ErrNotFound) {
		t.Fatalf("consume %s: got %v, want porte.ErrNotFound", hash, err)
	}
}
