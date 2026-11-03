package devicelogin

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// slowDownStep is RFC 8628 §3.5: on slow_down the client adds five seconds to
// its interval, for this request and every one after it. Ignoring it is how a
// client polls itself into a rate limit and reports the refusal as a failed
// login.
const slowDownStep = 5 * time.Second

// schedule is the polling clock. The interval lives here rather than being
// recomputed per response because slow_down is cumulative: two of them mean
// ten seconds more, not five. step is a field so a test can prove that
// arithmetic without sleeping through it.
type schedule struct {
	interval time.Duration
	step     time.Duration
	deadline time.Time
}

// wait sleeps out one interval and reports whether there is still time to
// poll. It returns false at once when ctx ends.
func (s *schedule) wait(ctx context.Context) bool {
	if !time.Now().Before(s.deadline) {
		return false
	}
	timer := time.NewTimer(s.interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// slower applies slow_down to every request from here on.
func (s *schedule) slower() { s.interval += s.step }

// Poll waits for the user to approve the sign-in and returns the provider's
// access token. It honours the interval, adds five seconds on every slow_down,
// keeps waiting on authorization_pending, and stops with ErrDenied on
// access_denied and ErrExpired on expired_token or once ExpiresIn has passed.
// A cancelled ctx returns ctx.Err() unchanged.
func (e Endpoints) Poll(ctx context.Context, clientID string, auth Authorization) (string, error) {
	return e.poll(ctx, clientID, auth, &schedule{
		interval: auth.Interval,
		step:     slowDownStep,
		deadline: time.Now().Add(auth.ExpiresIn),
	})
}

// poll is Poll with the clock supplied. A transport error is retried rather
// than fatal: the deadline already bounds the loop, and a dropped packet on the
// fourth poll is no reason to make somebody start again.
func (e Endpoints) poll(ctx context.Context, clientID string, auth Authorization, clock *schedule) (string, error) {
	for clock.wait(ctx) {
		status, doc, err := postForm(ctx, e.Token, url.Values{
			"grant_type":  {GrantType},
			"device_code": {auth.DeviceCode},
			"client_id":   {clientID},
		})
		if err != nil {
			continue
		}
		token, slower, err := read(status, doc)
		switch {
		case err != nil:
			return "", err
		case token != "":
			return token, nil
		case slower:
			clock.slower()
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%w, gave up after %s", ErrExpired, auth.ExpiresIn.Round(time.Second))
}

// read turns one poll answer into the three things that can happen: the grant
// completed, keep waiting (slower when the provider asked for it), or stop.
func read(status int, doc map[string]any) (string, bool, error) {
	if ok(status) {
		token := text(doc, "access_token")
		if token == "" {
			return "", false, fmt.Errorf("devicelogin: the provider approved the sign-in but sent no access token")
		}
		return token, false, nil
	}
	switch text(doc, "error") {
	case "authorization_pending":
		return "", false, nil
	case "slow_down":
		return "", true, nil
	case "access_denied":
		return "", false, ErrDenied
	case "expired_token":
		return "", false, ErrExpired
	}
	return "", false, fmt.Errorf("devicelogin: the provider refused the device grant (%d: %s)", status, refusal(doc))
}
