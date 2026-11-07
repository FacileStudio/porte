package pg_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/pg"
)

func secret(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func mustSealer(t *testing.T, secrets ...[]byte) *pg.TokenSealer {
	t.Helper()
	sealer, err := pg.NewTokenSealer(secrets...)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return sealer
}

func TestSealerRoundTripsWithAFreshNonce(t *testing.T) {
	sealer := mustSealer(t, secret(1))
	first, err := sealer.Seal("refresh-token-value")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	second, _ := sealer.Seal("refresh-token-value")
	if !strings.HasPrefix(first, "pv1:") || strings.Contains(first, "refresh-token-value") {
		t.Fatalf("not sealed: %q", first)
	}
	if first == second {
		t.Fatal("two seals of one value are identical: the nonce is not random")
	}
	plain, err := sealer.Open(first)
	if err != nil || plain != "refresh-token-value" {
		t.Fatalf("open = %q, %v", plain, err)
	}
}

func TestSealerEmptyAndPlaintextPassThrough(t *testing.T) {
	sealer := mustSealer(t, secret(1))
	if sealed, _ := sealer.Seal(""); sealed != "" {
		t.Fatalf("empty sealed to %q", sealed)
	}
	if plain, err := sealer.Open("legacy-plaintext"); err != nil || plain != "legacy-plaintext" {
		t.Fatalf("plaintext = %q, %v", plain, err)
	}
}

func TestSealerWrongKeyAndTamperingFailClosed(t *testing.T) {
	sealed, _ := mustSealer(t, secret(1)).Seal("tok")
	if _, err := mustSealer(t, secret(2)).Open(sealed); !errors.Is(err, pg.ErrTokenUnreadable) {
		t.Fatalf("wrong key: %v", err)
	}
	flipped := sealed[:len(sealed)-2] + "AA"
	if _, err := mustSealer(t, secret(1)).Open(flipped); !errors.Is(err, pg.ErrTokenUnreadable) {
		t.Fatalf("tampered: %v", err)
	}
	for _, junk := range []string{"pv1:", "pv1:!!", "pv1:AAAA"} {
		if _, err := mustSealer(t, secret(1)).Open(junk); !errors.Is(err, pg.ErrTokenUnreadable) {
			t.Fatalf("%q: %v", junk, err)
		}
	}
	var none *pg.TokenSealer
	if _, err := none.Open(sealed); !errors.Is(err, pg.ErrTokenUnreadable) {
		t.Fatalf("nil sealer returned a sealed value: %v", err)
	}
}

func TestSealerRotationOpensOldKeysAndSealsWithTheNewest(t *testing.T) {
	old, _ := mustSealer(t, secret(1)).Seal("tok")
	rotated := mustSealer(t, secret(2), secret(1))
	if plain, err := rotated.Open(old); err != nil || plain != "tok" {
		t.Fatalf("old key: %q, %v", plain, err)
	}
	fresh, _ := rotated.Seal("tok")
	if _, err := mustSealer(t, secret(1)).Open(fresh); err == nil {
		t.Fatal("the old key opened a value sealed under the new one")
	}
}

func TestSealerRejectsBadSecrets(t *testing.T) {
	if _, err := pg.NewTokenSealer(); err == nil {
		t.Fatal("no secret accepted")
	}
	if _, err := pg.NewTokenSealer([]byte("short")); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestParseTokenSealer(t *testing.T) {
	if sealer, err := pg.ParseTokenSealer("  "); sealer != nil || err != nil {
		t.Fatalf("empty = %v, %v", sealer, err)
	}
	hexKey := hex.EncodeToString(secret(1))
	b64Key := base64.StdEncoding.EncodeToString(secret(2))
	sealer, err := pg.ParseTokenSealer(hexKey + ", " + b64Key)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	old, _ := mustSealer(t, secret(2)).Seal("tok")
	if plain, err := sealer.Open(old); err != nil || plain != "tok" {
		t.Fatalf("second key: %q, %v", plain, err)
	}
	if _, err := pg.ParseTokenSealer("not-a-key"); err == nil {
		t.Fatal("garbage accepted")
	}
}
