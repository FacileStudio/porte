package jwt

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestAccessTokenClaimsAreParsed(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)
	exp := time.Now().Add(10 * time.Minute).Unix()

	raw := token(t, key, srv.URL, map[string]any{
		"aud":       []string{"registre", "other"},
		"exp":       exp,
		"client_id": "bulle",
		"jti":       "tok-1",
	})
	claims, err := newVerifier(t, srv.URL).Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reflect.DeepEqual(claims.Audience, []string{"registre", "other"}) {
		t.Errorf("Audience = %v", claims.Audience)
	}
	if claims.ClientID != "bulle" || claims.ID != "tok-1" {
		t.Errorf("ClientID = %q, ID = %q", claims.ClientID, claims.ID)
	}
	if claims.ExpiresAt.Unix() != exp {
		t.Errorf("ExpiresAt = %v, want %d", claims.ExpiresAt, exp)
	}
}

func TestExtraAudiencesAreAcceptedAndNothingElse(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)
	verifier, err := New(context.Background(), Config{
		Issuer: srv.URL, Audience: "https://app.example/mcp", ExtraAudiences: []string{"", "app"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, aud := range []string{"https://app.example/mcp", "app"} {
		if _, err := verifier.Verify(context.Background(), token(t, key, srv.URL, map[string]any{"aud": aud})); err != nil {
			t.Errorf("aud %q was refused: %v", aud, err)
		}
	}
	for _, aud := range []any{"registre", "", []string{}} {
		if _, err := verifier.Verify(context.Background(), token(t, key, srv.URL, map[string]any{"aud": aud})); err == nil {
			t.Errorf("aud %v verified", aud)
		}
	}
}
