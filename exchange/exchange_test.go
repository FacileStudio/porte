package exchange_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/exchange"
)

var (
	bulle    = exchange.Target{Audience: "bulle", Scopes: []string{"bulle.read", "bulle.write"}}
	courrier = exchange.Target{Audience: "courrier", Scopes: []string{"courrier.read"}}
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	registre *fakeRegistre
	ids      *memoryIdentities
	ex       *exchange.Exchanger
	clock    *clock
}

func setup(t *testing.T) fixture {
	t.Helper()
	registre := newFakeRegistre(t)
	ids := &memoryIdentities{rows: map[int64]porte.StoredIdentity{
		7: {UserID: 7, Provider: registre.issuer(), Subject: "sub-7", Tokens: porte.TokenSet{RefreshToken: registre.seed()}},
	}}
	c := &clock{now: time.Now()}
	ex, err := exchange.New(exchange.Config{
		Issuer: registre.issuer() + "/", ClientID: clientID, ClientSecret: secret, Identities: ids, Now: c.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{registre: registre, ids: ids, ex: ex, clock: c}
}

func tokensInParallel(f fixture, n int) []error {
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		target := bulle
		if i%2 == 1 {
			target = courrier
		}
		wg.Go(func() {
			token, err := f.ex.Token(context.Background(), 7, target)
			if err == nil && !strings.HasPrefix(token, "x-"+target.Audience+"-") {
				err = errors.New("wrong token " + token)
			}
			errs[i] = err
		})
	}
	wg.Wait()
	return errs
}

func TestParallelAudiencesRefreshOnce(t *testing.T) {
	f := setup(t)
	before := f.ids.refreshToken(7)
	if err := errors.Join(tokensInParallel(f, 40)...); err != nil {
		t.Fatal(err)
	}
	if got := f.registre.refreshes.Load(); got != 1 {
		t.Fatalf("refreshes = %d, want 1", got)
	}
	if got := f.registre.exchanges.Load(); got != 2 {
		t.Fatalf("exchanges = %d, want one per audience", got)
	}
	if f.registre.overlapping.Load() {
		t.Fatal("two refreshes ran at once")
	}
	if after := f.ids.refreshToken(7); after == before || after == "" {
		t.Fatalf("the rotated refresh token was not saved: %q", after)
	}
}

func TestCacheUntilExpiryMinusMargin(t *testing.T) {
	f := setup(t)
	first, err := f.ex.Token(context.Background(), 7, bulle)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(4 * time.Minute)
	if again, _ := f.ex.Token(context.Background(), 7, bulle); again != first {
		t.Fatalf("cached token not reused: %s then %s", first, again)
	}
	f.clock.advance(31 * time.Second)
	renewed, err := f.ex.Token(context.Background(), 7, bulle)
	if err != nil || renewed == first {
		t.Fatalf("token past expiry minus margin was reused: %s, %v", renewed, err)
	}
	if got := f.registre.refreshes.Load(); got != 1 {
		t.Fatalf("refreshes = %d, the Registre access token should still be valid", got)
	}
}

func TestRejectedSubjectRefreshesOnce(t *testing.T) {
	f := setup(t)
	if _, err := f.ex.Token(context.Background(), 7, bulle); err != nil {
		t.Fatal(err)
	}
	f.registre.revokeAccess()
	f.ex.Forget(7, bulle)
	if _, err := f.ex.Token(context.Background(), 7, bulle); err != nil {
		t.Fatalf("a rejected subject token should be refreshed and retried: %v", err)
	}
	if got := f.registre.refreshes.Load(); got != 2 {
		t.Fatalf("refreshes = %d, want 2", got)
	}
}

func TestDeadRefreshTokenIsReconnect(t *testing.T) {
	f := setup(t)
	f.ids.setRefreshToken(7, "rt-revoked")
	_, err := f.ex.Token(context.Background(), 7, bulle)
	if !errors.Is(err, exchange.ErrReconnect) {
		t.Fatalf("err = %v, want ErrReconnect", err)
	}
	if _, err := f.ex.Token(context.Background(), 99, bulle); !errors.Is(err, exchange.ErrReconnect) {
		t.Fatalf("a user with no identity: err = %v, want ErrReconnect", err)
	}
}

func TestRotationByAnotherReplica(t *testing.T) {
	f := setup(t)
	stale := f.ids.refreshToken(7)
	f.registre.mu.Lock()
	delete(f.registre.refresh, stale)
	f.registre.mu.Unlock()
	f.ids.setRefreshToken(7, f.registre.seed())
	f.ids.stale = stale
	if _, err := f.ex.Token(context.Background(), 7, bulle); err != nil {
		t.Fatalf("a token rotated elsewhere should be picked up: %v", err)
	}
	if got := f.registre.refreshes.Load(); got != 2 {
		t.Fatalf("refreshes = %d, want the refused one and the retry", got)
	}
}

func TestRefusedScopeIsNotReconnect(t *testing.T) {
	f := setup(t)
	_, err := f.ex.Token(context.Background(), 7, exchange.Target{Audience: "courrier", Scopes: []string{"courrier.write"}})
	var refused *exchange.RefusedError
	if !errors.As(err, &refused) || refused.Code != "invalid_scope" || errors.Is(err, exchange.ErrReconnect) {
		t.Fatalf("err = %v, want RefusedError invalid_scope", err)
	}
	f.registre.down.Store(true)
	f.ex.ForgetUser(7)
	if _, err := f.ex.Token(context.Background(), 7, bulle); !errors.Is(err, exchange.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestCancelledCallerStillPersistsRotation(t *testing.T) {
	f := setup(t)
	before := f.ids.refreshToken(7)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	_, _ = f.ex.Token(ctx, 7, bulle)
	if after := f.ids.refreshToken(7); after == before {
		t.Fatal("the rotation was lost when the caller went away")
	}
	if _, err := f.ex.Token(context.Background(), 7, bulle); err != nil {
		t.Fatalf("the next call should use the rotated token: %v", err)
	}
}

func TestUnsavedRotationIsKeptInMemory(t *testing.T) {
	f := setup(t)
	f.ids.failing.Store(true)
	if _, err := f.ex.Token(context.Background(), 7, bulle); err != nil {
		t.Fatal(err)
	}
	f.ids.failing.Store(false)
	f.registre.revokeAccess()
	f.ex.Forget(7, bulle)
	if _, err := f.ex.Token(context.Background(), 7, bulle); err != nil {
		t.Fatalf("the unsaved rotated token should be used and saved: %v", err)
	}
	if f.ids.saves.Load() != 1 {
		t.Fatalf("saves = %d, want 1", f.ids.saves.Load())
	}
}

func TestDoRetriesOnceOn401(t *testing.T) {
	f := setup(t)
	var seen []string
	call := func(_ context.Context, token string) (*http.Response, error) {
		seen = append(seen, token)
		status := http.StatusUnauthorized
		if len(seen) > 1 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Body: http.NoBody}, nil
	}
	ctx := porte.WithIdentity(context.Background(), porte.Identity{UserID: 7})
	response, err := f.ex.Source(bulle).Do(ctx, call)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Do = %v, %v", response, err)
	}
	if len(seen) != 2 || seen[0] == seen[1] {
		t.Fatalf("tokens = %v, want a fresh token on the retry", seen)
	}
	always := func(context.Context, string) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
	}
	if response, _ := f.ex.Do(ctx, 7, bulle, always); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("a second 401 should be returned")
	}
	if _, err := f.ex.Source(bulle).Token(context.Background()); !errors.Is(err, exchange.ErrNoUser) {
		t.Fatalf("no identity: err = %v", err)
	}
}
