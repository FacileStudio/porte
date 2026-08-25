package jwt

import (
	"context"
	"testing"
	"time"
)

// TestATokenThatIsNotValidYetIsRefused covers nbf. A token minted for a window
// that has not opened is not this request's credential, however good its
// signature is.
func TestATokenThatIsNotValidYetIsRefused(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	early := token(t, key, srv.URL, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()})
	if _, err := newVerifier(t, srv.URL).Verify(context.Background(), early); err == nil {
		t.Fatal("a token whose nbf has not arrived verified")
	}
}

// TestATokenIssuedInTheFutureIsRefused covers iat. A token stamped after this
// machine's clock is either a clock the suite cannot trust or a token minted
// to outlive a revocation, and neither should authenticate.
func TestATokenIssuedInTheFutureIsRefused(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	ahead := token(t, key, srv.URL, map[string]any{"iat": time.Now().Add(time.Hour).Unix()})
	if _, err := newVerifier(t, srv.URL).Verify(context.Background(), ahead); err == nil {
		t.Fatal("a token issued in the future verified")
	}
}

// TestNbfAndIatAreOptionalAndForgiveTheLeeway pins both halves of the optional
// rule: an access token that omits them verifies, and one whose stamps sit a
// few seconds ahead of this machine verifies too, because two servers
// disagreeing about the second is not an attack.
func TestNbfAndIatAreOptionalAndForgiveTheLeeway(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)
	verifier := newVerifier(t, srv.URL)

	if _, err := verifier.Verify(context.Background(), token(t, key, srv.URL, nil)); err != nil {
		t.Fatalf("a token carrying neither nbf nor iat was refused: %v", err)
	}

	skewed := token(t, key, srv.URL, map[string]any{
		"nbf": time.Now().Add(leeway / 2).Unix(),
		"iat": time.Now().Add(leeway / 2).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), skewed); err != nil {
		t.Fatalf("a token inside the clock leeway was refused: %v", err)
	}
}
