package jwt

import (
	"context"
	"fmt"
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

// unpublished signs a token under a kid the provider never published, which
// is what both a forged header and a key the verifier has not seen look like
// on the wire.
func unpublished(t *testing.T, issuer, kid string, overrides map[string]any) string {
	t.Helper()
	payload := map[string]any{"iss": issuer, "aud": "registre"}
	for claim, value := range overrides {
		payload[claim] = value
	}
	return sign(t, generateKey(t), kid, "RS256", payload)
}

func TestAnUnknownKidTriggersExactlyOneRefetchBeforeRefusing(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := now
	live := map[string]any{"exp": now.Add(time.Hour).Unix()}
	server, srv := newKeyServer(t)
	warm := generateKey(t)
	server.setKey("kid-1", &warm.PublicKey)
	verifier := newVerifierWithTTL(t, srv.URL, time.Hour, &clock)

	if _, err := verifier.Verify(context.Background(), token(t, warm, srv.URL, live)); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}
	before := server.fetchCount()

	rotated := mint(t, server, srv.URL, "kid-2", live)
	if _, err := verifier.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("rotated key should verify after one refetch: %v", err)
	}
	if got := server.fetchCount(); got != before+1 {
		t.Errorf("fetches after rotation = %d, want %d", got, before+1)
	}

	clock = clock.Add(minRefetchInterval)
	if _, err := verifier.Verify(context.Background(), unpublished(t, srv.URL, "kid-none", live)); err == nil {
		t.Fatal("a token signed by a key the provider never published verified")
	}
	if got := server.fetchCount(); got != before+2 {
		t.Errorf("the refusal should have cost exactly one more fetch, got %d, want %d", got, before+2)
	}
}

// TestForgedKidsCostOneFetchNotOnePerRequest pins the floor under the
// unknown-kid refetch. The kid is read off the header before any signature has
// been checked, so without the floor an unauthenticated stranger buys one
// outbound JWKS fetch per request — serialized under the mutex every real
// verification waits on, and pointed at the one provider all eleven apps
// share. The rotation it exists to serve must still get through afterwards.
func TestForgedKidsCostOneFetchNotOnePerRequest(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	clock := now
	live := map[string]any{"exp": now.Add(time.Hour).Unix()}
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)
	verifier := newVerifierWithTTL(t, srv.URL, time.Hour, &clock)

	if _, err := verifier.Verify(context.Background(), token(t, key, srv.URL, live)); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}
	before := server.fetchCount()

	for i := range 20 {
		forged := unpublished(t, srv.URL, fmt.Sprintf("forged-%d", i), live)
		if _, err := verifier.Verify(context.Background(), forged); err == nil {
			t.Fatalf("forged kid %d verified", i)
		}
	}
	if got := server.fetchCount(); got != before+1 {
		t.Errorf("a burst of forged kids cost %d fetches, want %d", got, before+1)
	}

	clock = clock.Add(minRefetchInterval)
	rotated := mint(t, server, srv.URL, "kid-2", live)
	if _, err := verifier.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("a real rotation past the floor must still be picked up: %v", err)
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
