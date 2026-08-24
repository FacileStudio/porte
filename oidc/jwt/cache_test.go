package jwt

import (
	"context"
	"testing"
	"time"
)

// mint signs a token under an explicit kid, which is what a key rotation
// looks like to this verifier: same issuer, new key id.
func mint(t *testing.T, server *keyServer, srvHost, kid string, overrides map[string]any) string {
	t.Helper()
	key := generateKey(t)
	server.setKey(kid, &key.PublicKey)
	payload := map[string]any{
		"iss": srvHost,
		"aud": "registre",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for claim, value := range overrides {
		payload[claim] = value
	}
	return sign(t, key, kid, "RS256", payload)
}

func TestAnUnknownKidTriggersExactlyOneRefetchBeforeRefusing(t *testing.T) {
	server, srv := newKeyServer(t)
	warm := generateKey(t)
	server.setKey("kid-1", &warm.PublicKey)
	verifier := newVerifier(t, srv.URL)

	if _, err := verifier.Verify(context.Background(), token(t, warm, srv.URL, nil)); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}
	before := server.fetchCount()

	rotated := mint(t, server, srv.URL, "kid-2", nil)
	if _, err := verifier.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("rotated key should verify after one refetch: %v", err)
	}
	if got := server.fetchCount(); got != before+1 {
		t.Errorf("fetches after rotation = %d, want %d", got, before+1)
	}

	unknown := sign(t, generateKey(t), "kid-none", "RS256", map[string]any{
		"iss": srv.URL,
		"aud": "registre",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), unknown); err == nil {
		t.Fatal("a token signed by a key the provider never published verified")
	}
	if got := server.fetchCount(); got != before+2 {
		t.Errorf("the refusal should have cost exactly one more fetch, got %d, want %d", got, before+2)
	}
}

func newVerifierWithTTL(t *testing.T, issuer string, ttl time.Duration, clock *time.Time) *Verifier {
	t.Helper()
	verifier, err := New(context.Background(), Config{
		Issuer:   issuer,
		Audience: "registre",
		CacheTTL: ttl,
		Now:      func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func TestTheCacheHonoursItsTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := now
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	verifier := newVerifierWithTTL(t, srv.URL, time.Minute, &clock)
	raw := token(t, key, srv.URL, map[string]any{"exp": now.Add(time.Hour).Unix()})

	for i := 0; i < 3; i++ {
		if _, err := verifier.Verify(context.Background(), raw); err != nil {
			t.Fatalf("verify %d inside the TTL: %v", i, err)
		}
	}
	if got := server.fetchCount(); got != 1 {
		t.Fatalf("fetches inside the TTL = %d, want 1", got)
	}

	clock = clock.Add(2 * time.Minute)
	if _, err := verifier.Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if got := server.fetchCount(); got != 2 {
		t.Errorf("fetches past the TTL = %d, want 2", got)
	}
}
