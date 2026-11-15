package pg_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte/pg"
)

const envSecret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

type logLine struct {
	message string
	count   int64
}

type recordingHandler struct {
	slog.Handler
	lines chan logLine
}

func (h recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h recordingHandler) Handle(_ context.Context, record slog.Record) error {
	line := logLine{message: record.Message, count: -1}
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "resealed" {
			line.count = attr.Value.Int64()
		}
		return true
	})
	h.lines <- line
	return nil
}

func recordingLogger() (*slog.Logger, chan logLine) {
	lines := make(chan logLine, 4)
	return slog.New(recordingHandler{lines: lines}), lines
}

func TestNewFromEnvRefusesAKeyItCannotRead(t *testing.T) {
	t.Setenv(pg.TokenKeyEnv, "not-a-key")
	store, err := pg.NewFromEnv(nil)
	if err == nil || store != nil {
		t.Fatalf("NewFromEnv = %v, %v, want no store and an error", store, err)
	}
	if !strings.Contains(err.Error(), "PORTE_TOKEN_KEY is set but invalid") {
		t.Fatalf("error %q does not name the variable", err)
	}
}

func TestNewFromEnvWithoutAKeyLeavesTokensInTheClear(t *testing.T) {
	_, db := open(t)
	t.Setenv(pg.TokenKeyEnv, "  ")
	store, err := pg.NewFromEnv(db)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	userID := seedUser(t, store, "sub-seal", "seal@facile.studio")
	saveTokens(t, store.Identities(), userID, "access", "refresh")
	if access, refresh := rawTokens(t, db); access != "access" || refresh != "refresh" {
		t.Fatalf("stored %q, %q, want the plaintext an unsealed store writes", access, refresh)
	}
}

func TestNewFromEnvSealsAndTheBackgroundPassCoversOlderRows(t *testing.T) {
	plain, db := open(t)
	userID := seedUser(t, plain, "sub-seal", "seal@facile.studio")
	saveTokens(t, plain.Identities(), userID, "access", "refresh")

	t.Setenv(pg.TokenKeyEnv, envSecret)
	store, err := pg.NewFromEnv(db)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	logger, lines := recordingLogger()
	pg.ResealInBackground(context.Background(), store, logger)

	select {
	case line := <-lines:
		if line.message != "porte token reseal complete" || line.count != 1 {
			t.Fatalf("logged %+v, want one resealed row", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the background reseal never reported")
	}
	if access, refresh := rawTokens(t, db); !strings.HasPrefix(access, "pv1:") || !strings.HasPrefix(refresh, "pv1:") {
		t.Fatalf("stored %q, %q, want both sealed", access, refresh)
	}
	if got := findTokens(t, store.Identities()); got.AccessToken != "access" || got.RefreshToken != "refresh" {
		t.Fatalf("read back %+v, want the original tokens", got)
	}
}

func TestResealInBackgroundDoesNothingWithoutASealer(t *testing.T) {
	logger, lines := recordingLogger()
	pg.ResealInBackground(context.Background(), pg.New(nil), logger)
	pg.ResealInBackground(context.Background(), nil, logger)
	select {
	case line := <-lines:
		t.Fatalf("logged %+v, want silence without a sealer", line)
	case <-time.After(50 * time.Millisecond):
	}
}
