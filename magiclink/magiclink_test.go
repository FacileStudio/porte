package magiclink

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	tronc "github.com/FacileStudio/tronc/errors"
)

func TestARequestMailsALinkThatSignsInOnce(t *testing.T) {
	r := newRig(t, Config{})
	r.request(t, "  Camille@Facile.Studio ", "10.0.0.1")

	mails := r.mail.mails()
	if len(mails) != 1 || mails[0].to != "camille@facile.studio" {
		t.Fatalf("want one mail to the normalised address, got %+v", mails)
	}
	token := r.mail.token(t)

	userID, w, err := r.consume(token)
	if err != nil || userID != 1 {
		t.Fatalf("consume: got (%d, %v), want (1, nil)", userID, err)
	}
	if r.sessions.issued() != 1 || len(w.Result().Cookies()) == 0 {
		t.Fatalf("consume must land in a cookie session: %d sessions, %d cookies", r.sessions.issued(), len(w.Result().Cookies()))
	}
	if _, _, err := r.consume(token); !errors.Is(err, porte.ErrMagicLinkInvalid) {
		t.Fatalf("a second consume must fail, got %v", err)
	}
	if r.sessions.issued() != 1 {
		t.Fatal("the replay minted a session")
	}
}

func TestOnlyTheHashOfTheTokenIsStored(t *testing.T) {
	r := newRig(t, Config{})
	r.request(t, "camille@facile.studio", "")
	token := r.mail.token(t)

	if len(r.links.created) != 1 {
		t.Fatalf("want one stored link, got %d", len(r.links.created))
	}
	stored := r.links.created[0]
	if stored.TokenHash == token || stored.TokenHash != porte.HashToken(token) {
		t.Fatalf("stored %q for token %q", stored.TokenHash, token)
	}
	if got := stored.ExpiresAt.Sub(stored.CreatedAt); got != porte.DefaultMagicLinkTTL {
		t.Fatalf("lifetime %v, want %v", got, porte.DefaultMagicLinkTTL)
	}
}

func TestALinkExpiresAtItsDeadline(t *testing.T) {
	r := newRig(t, Config{TTL: 10 * time.Minute})
	r.request(t, "camille@facile.studio", "")
	token := r.mail.token(t)

	r.now = clockStart.Add(10 * time.Minute)
	if _, _, err := r.consume(token); !errors.Is(err, porte.ErrMagicLinkInvalid) {
		t.Fatalf("an expired link must fail, got %v", err)
	}
}

func TestANewRequestSupersedesTheOlderLink(t *testing.T) {
	r := newRig(t, Config{})
	r.request(t, "camille@facile.studio", "")
	first := r.mail.token(t)
	r.now = clockStart.Add(time.Minute)
	r.request(t, "camille@facile.studio", "")
	second := r.mail.token(t)

	if _, _, err := r.consume(first); !errors.Is(err, porte.ErrMagicLinkInvalid) {
		t.Fatalf("the superseded link must fail, got %v", err)
	}
	if _, _, err := r.consume(second); err != nil {
		t.Fatalf("the newest link must work: %v", err)
	}
}

func deadTokens(t *testing.T, r *rig) map[string]string {
	t.Helper()
	r.request(t, "camille@facile.studio", "")
	superseded := r.mail.token(t)
	r.request(t, "camille@facile.studio", "")
	spent := r.mail.token(t)
	if _, _, err := r.consume(spent); err != nil {
		t.Fatalf("consume: %v", err)
	}
	r.request(t, "dana@facile.studio", "")
	r.refused[2] = true
	refused := r.mail.token(t)
	r.request(t, "eli@facile.studio", "")
	expired := r.mail.token(t)
	r.now = clockStart.Add(time.Hour)
	return map[string]string{
		"unknown": "not-a-token", "empty": "", "superseded": superseded, "spent": spent, "refused": refused, "expired": expired,
	}
}

func TestEveryDeadLinkIsTheSameError(t *testing.T) {
	r := newRig(t, Config{})
	tokens := deadTokens(t, r)
	var first error
	for name, token := range tokens {
		_, _, err := r.consume(token)
		if !errors.Is(err, porte.ErrMagicLinkInvalid) || tronc.Status(err) != 401 {
			t.Fatalf("%s: got %v (status %d)", name, err, tronc.Status(err))
		}
		if first == nil {
			first = err
		}
		if err.Error() != first.Error() {
			t.Fatalf("%s answers %q, others %q", name, err, first)
		}
	}
	if r.sessions.issued() != 1 {
		t.Fatalf("only the one good consume may mint a session, got %d", r.sessions.issued())
	}
}

func TestAnUnknownAddressIsIndistinguishableAndDoesTheSameReads(t *testing.T) {
	r := newRig(t, Config{})
	before := r.links.counts
	r.request(t, "camille@facile.studio", "10.0.0.1")
	known := r.links.counts - before
	before = r.links.counts
	r.request(t, "nobody@facile.studio", "10.0.0.1")
	r.request(t, "not an email", "10.0.0.1")
	unknown := (r.links.counts - before) / 2

	if known != unknown {
		t.Fatalf("a known address costs %d counts and an unknown one %d", known, unknown)
	}
	if len(r.mail.mails()) != 1 || len(r.links.created) != 1 {
		t.Fatalf("only the known address may mail and store: %d mails, %d rows", len(r.mail.mails()), len(r.links.created))
	}
}

func TestTheMailIsSentAfterRequestReturns(t *testing.T) {
	r := newRig(t, Config{})
	r.mail.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- r.kit.Request(context.Background(), "camille@facile.studio", "") }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("request: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Request waited for the mail server, so its duration would reveal the address")
	}
	close(r.mail.gate)
	r.kit.Wait()
	if len(r.mail.mails()) != 1 {
		t.Fatal("the mail was never sent")
	}
}

func TestAFailedMailIsLoggedWithoutTheToken(t *testing.T) {
	r := newRig(t, Config{})
	r.mail.fail = errors.New("smtp down")
	r.request(t, "camille@facile.studio", "")

	if !strings.Contains(r.logs.String(), "smtp down") {
		t.Fatalf("the failure was not logged: %q", r.logs.String())
	}
	if strings.Contains(r.logs.String(), r.links.created[0].TokenHash) || strings.Contains(r.logs.String(), "token=") {
		t.Fatalf("the log carries a credential: %q", r.logs.String())
	}
}

func TestThePerAddressLimitIsSilent(t *testing.T) {
	r := newRig(t, Config{MaxPerEmail: 2})
	for range 4 {
		r.request(t, "camille@facile.studio", "")
	}
	if got := len(r.mail.mails()); got != 2 {
		t.Fatalf("want 2 mails under a limit of 2, got %d", got)
	}
	r.now = clockStart.Add(porte.MagicLinkRateWindow + time.Minute)
	r.request(t, "camille@facile.studio", "")
	if got := len(r.mail.mails()); got != 3 {
		t.Fatalf("the window must reopen, got %d mails", got)
	}
}

func TestThePerSourceLimitCountsAcrossAccounts(t *testing.T) {
	r := newRig(t, Config{MaxPerIP: 2})
	for _, email := range []string{"camille@facile.studio", "dana@facile.studio", "eli@facile.studio"} {
		r.request(t, email, "10.0.0.9")
	}
	r.request(t, "camille@facile.studio", "10.0.0.10")
	if got := len(r.mail.mails()); got != 3 {
		t.Fatalf("want 2 mails from the capped source and 1 from another, got %d", got)
	}
}

func TestConcurrentConsumesHaveOneWinner(t *testing.T) {
	r := newRig(t, Config{})
	r.request(t, "camille@facile.studio", "")
	token := r.mail.token(t)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, _, err := r.consume(token); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || r.sessions.issued() != 1 {
		t.Fatalf("%d consumes won and %d sessions were minted, want 1 and 1", wins.Load(), r.sessions.issued())
	}
}

func TestNewRefusesAHalfWiredKit(t *testing.T) {
	if _, err := New(Config{}, Deps{}); err == nil {
		t.Fatal("a kit with no stores, mailer or sessions must not boot")
	}
}
