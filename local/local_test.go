package local

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/session"
)

// stores is every store this package writes through, in maps. The real ones
// are in porte/pg and are tested against a real PostgreSQL.
type stores struct {
	mu         sync.Mutex
	users      map[string]int64
	identities map[string]porte.StoredIdentity
	sessions   map[string]porte.Session
	nextID     int64
}

func newStores() *stores {
	return &stores{
		users:      map[string]int64{},
		identities: map[string]porte.StoredIdentity{},
		sessions:   map[string]porte.Session{},
	}
}

func (s *stores) CreateFromPassword(_ context.Context, email, _ string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.users[email] = s.nextID
	return s.nextID, nil
}

func (s *stores) FindByEmail(_ context.Context, email string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.users[email]; ok {
		return id, nil
	}
	return 0, porte.ErrNotFound
}

func (s *stores) count(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.users)), nil
}

func (s *stores) Find(_ context.Context, provider, subject string) (porte.StoredIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.identities[provider+"\x00"+subject]
	if !ok {
		return porte.StoredIdentity{}, porte.ErrNotFound
	}
	return identity, nil
}

func (s *stores) Save(_ context.Context, identity porte.StoredIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[identity.Provider+"\x00"+identity.Subject] = identity
	return nil
}

func (s *stores) MarkRolesSynced(context.Context, string, string, time.Time) error { return nil }

func (s *stores) ListByUser(_ context.Context, userID int64) ([]porte.StoredIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []porte.StoredIdentity
	for _, identity := range s.identities {
		if identity.UserID == userID {
			out = append(out, identity)
		}
	}
	return out, nil
}

func (s *stores) Create(_ context.Context, sess porte.Session) (porte.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	sess.ID = s.nextID
	s.sessions[sess.TokenHash] = sess
	return sess, nil
}

func (s *stores) FindSession(hash string) (porte.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[hash]
	return sess, ok
}

func (s *stores) Find2(_ context.Context, hash string) (porte.Session, error) {
	if sess, ok := s.FindSession(hash); ok {
		return sess, nil
	}
	return porte.Session{}, porte.ErrNotFound
}

func (s *stores) Touch(context.Context, string, time.Time) error { return nil }
func (s *stores) Delete(context.Context, string) error           { return nil }
func (s *stores) DeleteByUser(context.Context, int64) (int64, error) {
	return 0, nil
}
func (s *stores) DeleteByID(context.Context, int64, int64) error          { return nil }
func (s *stores) DeleteExpired(context.Context, time.Time) (int64, error) { return 0, nil }

// sessionStore adapts stores to porte.SessionStore, which needs a Find taking a
// token hash while IdentityStore.Find takes a provider and a subject. The two
// cannot live on one Go receiver, which is the same reason porte/pg hands out
// four types instead of one.
type sessionStore struct{ *stores }

func (s sessionStore) Find(ctx context.Context, hash string) (porte.Session, error) {
	return s.Find2(ctx, hash)
}

func (s sessionStore) ListByUser(_ context.Context, _ int64) ([]porte.Session, error) {
	return nil, nil
}

func testKit(t *testing.T, allowRegistration bool) (*Kit, *stores) {
	t.Helper()
	store := newStores()
	manager, err := session.New(porte.Config{}, session.Deps{Sessions: sessionStore{store}})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	kit, err := New(Config{AllowRegistration: allowRegistration}, Deps{
		Users:      store,
		Identities: store,
		Sessions:   manager,
		Count:      store.count,
	})
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return kit, store
}

func request() (*httptest.ResponseRecorder, *http.Request) {
	return httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/login", nil)
}

// The point of v0.2: a password login lands in the same session as a federated
// one, cookie included. v0.1 could not do this, so the first adopter's password
// path stayed on a token in localStorage.
func TestRegisterIssuesACookieSessionAndAHashedIdentity(t *testing.T) {
	kit, store := testKit(t, true)
	w, r := request()

	userID, token, err := kit.Register(context.Background(), w, r, "Someone@Facile.Studio ", "Someone", "a-long-enough-password")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if userID == 0 || token == "" {
		t.Fatal("register returned no account")
	}

	if _, ok := store.FindSession(porte.HashToken(token)); !ok {
		t.Fatal("no session row was written for the token handed to the caller")
	}
	var cookie *http.Cookie
	for _, candidate := range w.Result().Cookies() {
		if strings.HasSuffix(candidate.Name, porte.SessionCookieName) {
			cookie = candidate
		}
	}
	if cookie == nil || cookie.Value != token || !cookie.HttpOnly {
		t.Fatalf("expected an HttpOnly session cookie carrying the token, got %+v", cookie)
	}

	// The address is the identity's subject, normalised, and the password
	// is never at rest in the clear.
	identity, err := store.Find(context.Background(), porte.ProviderLocal, "someone@facile.studio")
	if err != nil {
		t.Fatalf("identity not stored under the normalised address: %v", err)
	}
	if identity.PasswordHash == "" || strings.Contains(identity.PasswordHash, "a-long-enough-password") {
		t.Fatalf("password is not hashed: %q", identity.PasswordHash)
	}
	if !VerifyPassword("a-long-enough-password", identity.PasswordHash) {
		t.Fatal("the stored hash does not verify the password it was made from")
	}
}

// An unknown address and a wrong password must be indistinguishable. Different
// errors here turn the login form into an account enumeration oracle.
func TestAnUnknownAddressAndAWrongPasswordAreTheSameAnswer(t *testing.T) {
	kit, _ := testKit(t, true)
	w, r := request()
	if _, _, err := kit.Register(context.Background(), w, r, "someone@facile.studio", "", "a-long-enough-password"); err != nil {
		t.Fatalf("register: %v", err)
	}

	w, r = request()
	_, _, wrong := kit.Login(context.Background(), w, r, "someone@facile.studio", "not-the-password")
	w, r = request()
	_, _, unknown := kit.Login(context.Background(), w, r, "nobody@facile.studio", "not-the-password")

	if wrong == nil || unknown == nil {
		t.Fatal("a bad login succeeded")
	}
	if wrong.Error() != unknown.Error() {
		t.Fatalf("the two answers differ: %q vs %q", wrong, unknown)
	}
}

func TestLoginIssuesASessionForTheRightPassword(t *testing.T) {
	kit, store := testKit(t, true)
	w, r := request()
	registered, _, err := kit.Register(context.Background(), w, r, "someone@facile.studio", "", "a-long-enough-password")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	w, r = request()
	userID, token, err := kit.Login(context.Background(), w, r, "SOMEONE@facile.studio", "a-long-enough-password")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if userID != registered {
		t.Fatalf("login resolved to %d, registered %d", userID, registered)
	}
	if _, ok := store.FindSession(porte.HashToken(token)); !ok {
		t.Fatal("login issued a token with no session row")
	}
}

// The first account is always creatable. Locking an empty instance out of
// itself is not a security property, and every app in the suite carries this
// exception already.
func TestRegistrationClosedStillAllowsTheFirstAccount(t *testing.T) {
	kit, _ := testKit(t, false)

	w, r := request()
	if _, _, err := kit.Register(context.Background(), w, r, "first@facile.studio", "", "a-long-enough-password"); err != nil {
		t.Fatalf("the first account was refused: %v", err)
	}

	w, r = request()
	_, _, err := kit.Register(context.Background(), w, r, "second@facile.studio", "", "a-long-enough-password")
	if err == nil {
		t.Fatal("a second account was created with registration closed")
	}
}

// A human who already signed in through the identity provider and then sets a
// password is the same account, not a second one. That is the whole reason
// identities live in their own table.
// TestRegisteringAFederatedAddressIsRefused is the regression test for the
// account takeover this package shipped until v0.2.3.
//
// An account created by SSO has no local identity. Register used to read that
// as "the same human is adding a password", write the caller's hash onto that
// account and issue a session for it — so anyone who knew the address of an
// SSO user owned their account, on an open registration form.
func TestRegisteringAFederatedAddressIsRefused(t *testing.T) {
	kit, store := testKit(t, true)

	victim, err := store.CreateFromPassword(context.Background(), "someone@facile.studio", "Someone")
	if err != nil {
		t.Fatalf("seed the federated user: %v", err)
	}
	if err := store.Save(context.Background(), porte.StoredIdentity{
		UserID: victim, Provider: "https://sso.test/", Subject: "abc",
	}); err != nil {
		t.Fatalf("seed the federated identity: %v", err)
	}

	w, r := request()
	_, token, err := kit.Register(context.Background(), w, r, "someone@facile.studio", "Attacker", "a-long-enough-password")
	if err == nil {
		t.Fatal("registering an address that already has an SSO account was allowed")
	}
	if !stderrors.Is(err, porte.ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}
	if token != "" {
		t.Fatal("a session was issued for an account the caller does not own")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("a session cookie was set for an account the caller does not own")
	}

	identities, err := store.ListByUser(context.Background(), victim)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("a password was attached to the victim's account: %d identities", len(identities))
	}

	// The refusal must not be cheaper than the creation it refuses, or the
	// response time answers "does this address have an account" on its own.
	// The floor is deliberately far below one argon2 hash: this asserts the
	// hash happened at all, not how fast the machine is.
	start := time.Now()
	w, r = request()
	_, _, _ = kit.Register(context.Background(), w, r, "someone@facile.studio", "", "another-long-password")
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Fatalf("the refusal skipped the timing equaliser: %s", elapsed)
	}
}

// TestSetPasswordIsHowAFederatedAccountGainsAPassword pins the supported
// replacement for what Register used to do. It takes a user id, so the caller
// has already proved who they are; Register never can.
func TestSetPasswordIsHowAFederatedAccountGainsAPassword(t *testing.T) {
	kit, store := testKit(t, true)

	federated, err := store.CreateFromPassword(context.Background(), "someone@facile.studio", "Someone")
	if err != nil {
		t.Fatalf("seed the federated user: %v", err)
	}
	if err := store.Save(context.Background(), porte.StoredIdentity{
		UserID: federated, Provider: "https://sso.test/", Subject: "abc",
	}); err != nil {
		t.Fatalf("seed the federated identity: %v", err)
	}

	if err := kit.SetPassword(context.Background(), federated, "someone@facile.studio", "a-long-enough-password"); err != nil {
		t.Fatalf("SetPassword on a federated account: %v", err)
	}

	identities, err := store.ListByUser(context.Background(), federated)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("expected two identities on one human, got %d", len(identities))
	}

	w, r := request()
	userID, _, err := kit.Login(context.Background(), w, r, "someone@facile.studio", "a-long-enough-password")
	if err != nil {
		t.Fatalf("the password set on the federated account does not sign in: %v", err)
	}
	if userID != federated {
		t.Fatalf("signed into a different account: %d then %d", federated, userID)
	}
}

func TestPasswordFloorIsEnforced(t *testing.T) {
	kit, _ := testKit(t, true)
	w, r := request()
	if _, _, err := kit.Register(context.Background(), w, r, "someone@facile.studio", "", "short"); err == nil {
		t.Fatal("an 11-character password was accepted")
	}
}

// An account created through SSO has no password identity, so no password can
// sign into it — including the empty one.
func TestAnSSOOnlyAccountCannotBeSignedIntoWithAPassword(t *testing.T) {
	kit, store := testKit(t, true)
	if _, err := store.CreateFromPassword(context.Background(), "someone@facile.studio", "Someone"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	for _, password := range []string{"", "guess", "a-long-enough-password"} {
		w, r := request()
		if _, _, err := kit.Login(context.Background(), w, r, "someone@facile.studio", password); err == nil {
			t.Fatalf("signed in to a passwordless account with %q", password)
		}
	}
}

func TestSetPasswordReplacesTheHash(t *testing.T) {
	kit, _ := testKit(t, true)
	w, r := request()
	userID, _, err := kit.Register(context.Background(), w, r, "someone@facile.studio", "", "a-long-enough-password")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := kit.SetPassword(context.Background(), userID, "someone@facile.studio", "a-different-long-password"); err != nil {
		t.Fatalf("set password: %v", err)
	}

	w, r = request()
	if _, _, err := kit.Login(context.Background(), w, r, "someone@facile.studio", "a-long-enough-password"); err == nil {
		t.Fatal("the old password still works")
	}
	w, r = request()
	if _, _, err := kit.Login(context.Background(), w, r, "someone@facile.studio", "a-different-long-password"); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
}

func TestHashPasswordProducesAVerifiableDistinctHashEachTime(t *testing.T) {
	first, err := HashPassword("a-long-enough-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, err := HashPassword("a-long-enough-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if first == second {
		t.Fatal("two hashes of one password are identical, so the salt is not random")
	}
	if !strings.HasPrefix(first, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("the encoding drifted from what the apps already store: %q", first)
	}
	for _, encoded := range []string{first, second} {
		if !VerifyPassword("a-long-enough-password", encoded) {
			t.Fatal("a hash does not verify its own password")
		}
	}
	for _, malformed := range []string{"", "$argon2id$", "not-a-hash", "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA"} {
		if VerifyPassword("anything", malformed) {
			t.Fatalf("a malformed encoding verified: %q", malformed)
		}
	}
}

// The contract says the sentinels exist so a handler can map them to a status
// without matching on message text. That is only true if they are wrapped.
func TestTheSentinelsAreMatchable(t *testing.T) {
	kit, _ := testKit(t, true)
	ctx := context.Background()

	w, r := request()
	if _, _, err := kit.Register(ctx, w, r, "someone@facile.studio", "", "a-long-enough-password"); err != nil {
		t.Fatalf("register: %v", err)
	}

	cases := []struct {
		name string
		call func() error
		want error
	}{
		{"wrong password", func() error {
			w, r := request()
			_, _, err := kit.Login(ctx, w, r, "someone@facile.studio", "wrong")
			return err
		}, porte.ErrWrongPassword},
		{"unknown address", func() error {
			w, r := request()
			_, _, err := kit.Login(ctx, w, r, "nobody@facile.studio", "wrong")
			return err
		}, porte.ErrWrongPassword},
		{"address already taken", func() error {
			w, r := request()
			_, _, err := kit.Register(ctx, w, r, "someone@facile.studio", "", "a-long-enough-password")
			return err
		}, porte.ErrEmailTaken},
		{"password too short", func() error {
			w, r := request()
			_, _, err := kit.Register(ctx, w, r, "other@facile.studio", "", "short")
			return err
		}, porte.ErrWeakPassword},
		{"not an address", func() error {
			w, r := request()
			_, _, err := kit.Register(ctx, w, r, "not-an-address", "", "a-long-enough-password")
			return err
		}, porte.ErrInvalidEmail},
	}
	for _, testCase := range cases {
		err := testCase.call()
		if err == nil {
			t.Errorf("%s: no error", testCase.name)
			continue
		}
		if !stderrors.Is(err, testCase.want) {
			t.Errorf("%s: %v does not match %v", testCase.name, err, testCase.want)
		}
	}

	closed, _ := testKit(t, false)
	w, r = request()
	if _, _, err := closed.Register(ctx, w, r, "first@facile.studio", "", "a-long-enough-password"); err != nil {
		t.Fatalf("first account: %v", err)
	}
	w, r = request()
	err := func() error {
		_, _, err := closed.Register(ctx, w, r, "second@facile.studio", "", "a-long-enough-password")
		return err
	}()
	if !stderrors.Is(err, porte.ErrRegistrationClosed) {
		t.Errorf("registration closed: %v does not match %v", err, porte.ErrRegistrationClosed)
	}
}
