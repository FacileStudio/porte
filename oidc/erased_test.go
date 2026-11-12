package oidc

import (
	"context"
	stderrors "errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/directory"
	"github.com/FacileStudio/tronc/errors"
)

var _ porte.ErasedSubjects = (*directory.Deletions)(nil)

type ledger struct {
	mu     sync.Mutex
	erased map[string]bool
	fail   bool
}

func (l *ledger) Erased(_ context.Context, provider, subject string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return false, stderrors.New("db is down")
	}
	return l.erased[provider+"|"+subject], nil
}

func (l *ledger) erase(provider, subject string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.erased[provider+"|"+subject] = true
}

func erasedHarness(t *testing.T) (*harness, *countingUsers, *ledger) {
	t.Helper()
	h, users := provisionHarness(t, nil)
	l := &ledger{erased: map[string]bool{}}
	h.kit.deps.Erased = l
	return h, users, l
}

func TestTheCallbackRefusesAnErasedSubject(t *testing.T) {
	h, users, l := erasedHarness(t)
	l.erase(h.idp.issuer(), "subject-1")
	response := h.login(t, h.client(t), "")
	assertLoginRefused(t, response)
	if users.calls.Load() != 0 {
		t.Fatalf("an erased subject reached UpsertFromOIDC %d times", users.calls.Load())
	}
}

func TestProvisionBearerRefusesAnErasedSubject(t *testing.T) {
	h, users, l := erasedHarness(t)
	l.erase(h.idp.issuer(), "registre-sub")
	_, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	var apiErr *errors.Error
	if !stderrors.Is(err, ErrProvisionRefused) || !stderrors.Is(err, porte.ErrSubjectErased) ||
		!stderrors.As(err, &apiErr) || apiErr.Code != "permission_denied" {
		t.Fatalf("ProvisionBearer = %v, want a permission_denied refusal wrapping ErrSubjectErased", err)
	}
	if users.calls.Load() != 0 {
		t.Fatalf("an erased subject reached UpsertFromOIDC %d times", users.calls.Load())
	}
}

func TestAnUnreadableLedgerFailsClosedButIsNoRefusal(t *testing.T) {
	h, users, l := erasedHarness(t)
	l.fail = true
	_, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if err == nil || stderrors.Is(err, ErrProvisionRefused) || users.calls.Load() != 0 {
		t.Fatalf("ProvisionBearer = %v after %d upserts, want an internal failure and no account",
			err, users.calls.Load())
	}
}

func TestOtherSubjectsSignInBesideAnErasedOne(t *testing.T) {
	h, _, l := erasedHarness(t)
	l.erase(h.idp.issuer(), "someone-erased")
	if _, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true))); err != nil {
		t.Fatalf("ProvisionBearer: %v", err)
	}
	if response := h.login(t, h.client(t), ""); response.StatusCode != http.StatusFound ||
		response.Header.Get("Location") != h.app.URL+"/welcome" {
		t.Fatalf("login = %d to %q, want the success URL", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestSyncProfileRefusesASubjectErasedAfterSignIn(t *testing.T) {
	h, users, l := erasedHarness(t)
	client := h.client(t)
	_ = h.login(t, client, "")
	l.erase(h.idp.issuer(), "subject-1")
	h.advance(porte.DefaultProfileSyncInterval + time.Minute)
	response := h.syncProfile(t, client)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden || users.calls.Load() != 1 {
		t.Fatalf("sync-profile = %d after %d upserts, want 403 and only the login's upsert",
			response.StatusCode, users.calls.Load())
	}
}
