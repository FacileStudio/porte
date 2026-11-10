package oidc

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	jwtpkg "github.com/FacileStudio/porte/oidc/jwt"
	"github.com/FacileStudio/tronc/errors"
)

type countingUsers struct {
	next   porte.UserStore
	calls  atomic.Int64
	delay  time.Duration
	refuse error
}

func (c *countingUsers) UpsertFromOIDC(ctx context.Context, claims porte.Claims) (int64, error) {
	c.calls.Add(1)
	time.Sleep(c.delay)
	if c.refuse != nil {
		return 0, c.refuse
	}
	return c.next.UpsertFromOIDC(ctx, claims)
}

func provisionHarness(t *testing.T, configure func(*porte.Config)) (*harness, *countingUsers) {
	t.Helper()
	h := newHarness(t, configure)
	users := &countingUsers{next: h.stores}
	h.kit.deps.Users = users
	return h, users
}

func bearerClaims(verified *bool) jwtpkg.Claims {
	return jwtpkg.Claims{
		Subject: "registre-sub",
		Email:   " New@Example.com ",
		Name:    "New Person",
		Profile: jwtpkg.Profile{EmailVerified: verified, Picture: "https://sso.example/p/1", Locale: "fr"},
	}
}

func verified(value bool) *bool { return &value }

func TestProvisionBearerCreatesTheAccountTheLoginWould(t *testing.T) {
	h, users := provisionHarness(t, nil)
	identity, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if err != nil {
		t.Fatalf("ProvisionBearer: %v", err)
	}
	if identity.UserID == 0 || identity.Subject != "registre-sub" {
		t.Fatalf("identity = %+v, want the new account for registre-sub", identity)
	}
	got := h.stores.lastClaims
	if got.Provider != h.idp.issuer() || got.Email != "new@example.com" || !got.EmailVerified ||
		got.Name != "New Person" || got.Picture != "https://sso.example/p/1" || got.Locale != "fr" {
		t.Fatalf("the store saw %+v, want the login's normalised claims", got)
	}
	stored, err := identityStore{h.stores}.Find(context.Background(), h.idp.issuer(), "registre-sub")
	if err != nil || stored.UserID != identity.UserID {
		t.Fatalf("identity row = %+v, %v; want one naming account %d", stored, err, identity.UserID)
	}
	again, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if err != nil || again.UserID != identity.UserID || users.calls.Load() != 1 {
		t.Fatalf("second call = %+v, %v after %d upserts; want the same account, one upsert",
			again, err, users.calls.Load())
	}
}

func TestProvisionBearerRefusesAnEmailNobodyVouchedFor(t *testing.T) {
	cases := map[string]jwtpkg.Claims{
		"explicit false": bearerClaims(verified(false)),
		"silence":        bearerClaims(nil),
		"no email":       {Subject: "registre-sub", Profile: jwtpkg.Profile{EmailVerified: verified(true)}},
	}
	for name, claims := range cases {
		h, users := provisionHarness(t, func(cfg *porte.Config) { cfg.TrustEmailWithoutVerifiedClaim = name == "explicit false" })
		_, err := h.kit.ProvisionBearer(context.Background(), claims)
		if !stderrors.Is(err, ErrProvisionRefused) || users.calls.Load() != 0 {
			t.Fatalf("%s: err = %v after %d upserts, want a refusal before the store", name, err, users.calls.Load())
		}
	}
}

func TestProvisionBearerRefusesWhatTheStoreRefuses(t *testing.T) {
	h, users := provisionHarness(t, nil)
	users.refuse = errors.Forbidden("this account is disabled")
	_, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if !stderrors.Is(err, ErrProvisionRefused) {
		t.Fatalf("err = %v, want the store's refusal as ErrProvisionRefused", err)
	}
	if _, err := (identityStore{h.stores}).Find(context.Background(), h.idp.issuer(), "registre-sub"); err == nil {
		t.Fatal("a refused provisioning still wrote an identity row")
	}
	users.refuse = errors.Internal("the database is down", nil)
	_, err = h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if err == nil || stderrors.Is(err, ErrProvisionRefused) {
		t.Fatalf("err = %v, want a store failure that is not a refusal", err)
	}
}

func TestProvisionBearerLeavesAnExistingAccountAlone(t *testing.T) {
	h, users := provisionHarness(t, nil)
	existing := porte.StoredIdentity{UserID: 7, Provider: h.idp.issuer(), Subject: "registre-sub"}
	if err := (identityStore{h.stores}).Save(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	identity, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if err != nil || identity.UserID != 7 || users.calls.Load() != 0 {
		t.Fatalf("identity = %+v, %v after %d upserts; want account 7 untouched", identity, err, users.calls.Load())
	}
}

func TestConcurrentFirstCallsCreateOneAccount(t *testing.T) {
	h, users := provisionHarness(t, nil)
	users.delay = 50 * time.Millisecond
	ids := make([]int64, 16)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Go(func() {
			identity, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
			if err != nil {
				t.Errorf("call %d: %v", i, err)
			}
			ids[i] = identity.UserID
		})
	}
	wg.Wait()
	for i, id := range ids {
		if id != ids[0] || id == 0 {
			t.Fatalf("call %d resolved account %d, call 0 resolved %d", i, id, ids[0])
		}
	}
	if calls := users.calls.Load(); calls != 1 {
		t.Fatalf("%d upserts for one subject, want 1", calls)
	}
}

func TestProvisionBearerNeedsRolesWhenTheLoginDoes(t *testing.T) {
	h, users := provisionHarness(t, func(cfg *porte.Config) { cfg.ClaimsScope = "facile" })
	_, err := h.kit.ProvisionBearer(context.Background(), bearerClaims(verified(true)))
	if !stderrors.Is(err, ErrProvisionRefused) || users.calls.Load() != 0 {
		t.Fatalf("err = %v, want a refusal for a token without roles", err)
	}
	claims := bearerClaims(verified(true))
	claims.Roles = []string{"admin"}
	if _, err := h.kit.ProvisionBearer(context.Background(), claims); err != nil {
		t.Fatalf("with roles: %v", err)
	}
	if got := h.stores.lastClaims.Roles; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("roles reaching the store = %v, want [admin]", got)
	}
}
