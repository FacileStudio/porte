package jwt

import (
	"context"
	"reflect"
	"testing"
)

func TestScopeAndActorAreParsedFromADelegatedToken(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	raw := token(t, key, srv.URL, map[string]any{
		"scope": "courrier.read  agenda.read",
		"act":   map[string]any{"sub": "bulle", "act": map[string]any{"sub": "nested"}},
	})
	claims, err := newVerifier(t, srv.URL).Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("a delegated token was refused: %v", err)
	}
	if want := []string{"courrier.read", "agenda.read"}; !reflect.DeepEqual(claims.Scopes, want) {
		t.Errorf("Scopes = %v, want %v", claims.Scopes, want)
	}
	if claims.Actor != "bulle" {
		t.Errorf("Actor = %q, want bulle — a nested act must be ignored", claims.Actor)
	}
}

func TestATokenWithoutScopeOrActorYieldsNeither(t *testing.T) {
	server, srv := newKeyServer(t)
	key := generateKey(t)
	server.setKey("kid-1", &key.PublicKey)

	claims, err := newVerifier(t, srv.URL).Verify(context.Background(), token(t, key, srv.URL, nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.Scopes) != 0 || claims.Actor != "" {
		t.Errorf("Scopes = %v, Actor = %q, want neither", claims.Scopes, claims.Actor)
	}
}
