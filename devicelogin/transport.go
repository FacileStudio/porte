package devicelogin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout bounds one request to the provider or the app. The wait for
// the human is bounded by the code's expiry instead, never by this.
const requestTimeout = 15 * time.Second

// maxBody caps what a response may make this package read.
const maxBody = 1 << 20

// client carries the timeout. It is a value rather than http.DefaultClient so a
// CLI that tunes the default for its own API does not change this login.
var client = &http.Client{Timeout: requestTimeout}

// postForm sends application/x-www-form-urlencoded, which is what an OAuth
// endpoint takes.
func postForm(ctx context.Context, target string, form url.Values) (int, map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return send(request)
}

// send performs a request and decodes whatever JSON came back. A body that is
// not JSON decodes to nil rather than failing, because the status line is still
// worth reporting. The returned error wraps ctx.Err() when the context ended,
// so errors.Is(err, context.Canceled) holds for the caller.
func send(request *http.Request) (int, map[string]any, error) {
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if ctxErr := request.Context().Err(); ctxErr != nil {
			return 0, nil, ctxErr
		}
		return 0, nil, fmt.Errorf("devicelogin: cannot reach %s: %w", request.URL.Host, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		return response.StatusCode, nil, fmt.Errorf("devicelogin: cannot read the answer from %s: %w", request.URL.Host, err)
	}
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	return response.StatusCode, doc, nil
}

// refusal is the most useful sentence an error body carries. RFC 6749 §5.2
// makes error_description optional, and an app answers with its own shape, so
// this falls through to whatever field is there rather than an empty reason.
func refusal(doc map[string]any) string {
	for _, key := range []string{"error_description", "error", "message"} {
		if value := text(doc, key); value != "" {
			return value
		}
	}
	return "no reason given"
}

// text reads a string field, or "" when it is absent or not a string.
func text(doc map[string]any, key string) string {
	value, _ := doc[key].(string)
	return value
}

// seconds reads a duration stated in whole seconds, falling back when nothing
// usable is there. A zero interval would busy-poll the provider and a zero
// expiry would end the wait before it started.
func seconds(doc map[string]any, key string, fallback time.Duration) time.Duration {
	value, _ := doc[key].(float64)
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Second
}

// ok reports a 2xx status.
func ok(status int) bool {
	return status >= 200 && status <= 299
}
