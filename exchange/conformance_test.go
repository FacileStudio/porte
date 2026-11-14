package exchange_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/exchange"
)

const (
	vectorPath     = "../conformance/vectors/exchange_errors.json"
	vectorSource   = "github.com/FacileStudio/porte@v0.20.1"
	vectorIssuer   = "https://sso.test"
	vectorEndpoint = vectorIssuer + "/oauth/token"
)

var update = flag.Bool("update", false, "rewrite "+vectorPath)

type exchangeReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

type cannedRegistre struct{ exchange exchangeReply }

func answer(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func (c cannedRegistre) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet {
		return answer(http.StatusOK, `{"token_endpoint":"`+vectorEndpoint+`"}`), nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	if r.PostForm.Get("grant_type") == "refresh_token" {
		return answer(http.StatusOK, `{"access_token":"registre-at","refresh_token":"rt-2","expires_in":300}`), nil
	}
	return answer(c.exchange.Status, c.exchange.Body), nil
}

func exchangeOutcome(t *testing.T, in exchangeReply) map[string]any {
	t.Helper()
	ids := &memoryIdentities{rows: map[int64]porte.StoredIdentity{
		7: {UserID: 7, Provider: vectorIssuer, Subject: "sub-7", Tokens: porte.TokenSet{RefreshToken: "rt-1"}},
	}}
	ex, err := exchange.New(exchange.Config{
		Issuer: vectorIssuer, ClientID: clientID, ClientSecret: secret, Identities: ids,
		Client: &http.Client{Transport: cannedRegistre{exchange: in}},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := ex.Token(context.Background(), 7, bulle)
	var refused *exchange.RefusedError
	switch {
	case err == nil:
		return map[string]any{"outcome": "token", "token": token}
	case errors.Is(err, exchange.ErrReconnect):
		return map[string]any{"outcome": "reconnect"}
	case errors.Is(err, exchange.ErrUnavailable):
		return map[string]any{"outcome": "unavailable"}
	case errors.As(err, &refused):
		return map[string]any{"outcome": "refused", "status": refused.Status, "code": refused.Code}
	}
	t.Fatalf("an unclassified exchange error: %v", err)
	return nil
}

func exchangeInputs() map[string]exchangeReply {
	return map[string]exchangeReply{
		"a token":                         {200, `{"access_token":"bulle-at","expires_in":300}`},
		"a 200 with no access token":      {200, `{"expires_in":300}`},
		"a 200 that is not JSON":          {200, `<html>`},
		"invalid_grant":                   {400, `{"error":"invalid_grant"}`},
		"invalid_scope":                   {400, `{"error":"invalid_scope"}`},
		"invalid_target":                  {400, `{"error":"invalid_target"}`},
		"unauthorized_client":             {400, `{"error":"unauthorized_client"}`},
		"invalid_client":                  {401, `{"error":"invalid_client"}`},
		"a 4xx with no error code":        {403, `{}`},
		"a 4xx that is not JSON":          {400, `<html>`},
		"a 500":                           {500, `{"error":"server_error"}`},
		"a 502 naming invalid_grant":      {502, `{"error":"invalid_grant"}`},
		"a 503 with an empty body":        {503, ``},
		"a 429 is a refusal, not a retry": {429, `{"error":"slow_down"}`},
	}
}

func TestExchangeErrorVector(t *testing.T) {
	inputs := exchangeInputs()
	cases := []map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(inputs)) {
		cases = append(cases, map[string]any{"name": name, "input": inputs[name], "want": exchangeOutcome(t, inputs[name])})
	}
	got := encodeVector(t, map[string]any{
		"source": vectorSource, "subject": "exchange_errors",
		"fixtures": map[string]any{
			"note":      "the refresh always succeeds; input is the token endpoint's answer to the RFC 8693 exchange",
			"reconnect": map[string]any{"status": 412, "code": "failed_precondition"},
		},
		"cases": cases,
	})
	compareVector(t, got)
}

func encodeVector(t *testing.T, value any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func compareVector(t *testing.T, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(vectorPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s no longer matches what exchange does; review, then run go test ./exchange -update", vectorPath)
	}
}
