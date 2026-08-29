package loopback

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// waitTimeout bounds a single login attempt. It is long enough for a first-time
// browser sign-in with a password manager and an MFA prompt, and short enough
// that an abandoned terminal does not sit on an open port forever.
const waitTimeout = 3 * time.Minute

// shutdownGrace lets the page finish reaching the browser after the code has
// been read. Without it the process exits on the next line and the user's
// reward for signing in is a reset connection.
const shutdownGrace = 2 * time.Second

// WaitForCode serves the login callback and returns the one-time code porte
// redirected back with. It gives up when ctx is cancelled, Ctrl-C, or after
// waitTimeout, whichever comes first, and answers ErrTimeout for the second.
//
// Only a request to / that carries a code and echoes state back is accepted.
// Anything else is answered and ignored, and the listener keeps waiting: a
// browser asks for /favicon.ico without being told to, and ending the login
// over that produces a failure the user cannot diagnose. Refusing a mismatched
// state is the other half of the same rule. Without it, any page the user has
// open can hit http://127.0.0.1:<port>/?code=... and hand this CLI a session
// that is not the user's.
//
// The state comparison is an exact string match, deliberately kept over a
// constant-time one: the nonce is compared once per request against a listener
// that is not reachable off the machine, and a timing oracle needs a caller who
// can already run code on it.
func (l *Listener) WaitForCode(ctx context.Context, state string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()

	codes := make(chan string, 1)
	failures := make(chan error, 1)

	server := &http.Server{Handler: l.callback(state, codes)}
	server.SetKeepAlivesEnabled(false)

	go func() {
		if err := server.Serve(l.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failures <- err
		}
	}()

	defer func() {
		grace, stop := context.WithTimeout(context.Background(), shutdownGrace)
		defer stop()
		_ = server.Shutdown(grace)
	}()

	select {
	case code := <-codes:
		return code, nil
	case err := <-failures:
		return "", fmt.Errorf("loopback: the login listener failed: %w", err)
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("%w, gave up after %s", ErrTimeout, waitTimeout)
		}
		return "", ctx.Err()
	}
}

// callback is the handler the browser lands on, holding the acceptance rules
// WaitForCode documents.
//
// It parks an accepted code without blocking. A browser that reloads the
// callback, or two requests racing in, would otherwise leave a handler waiting
// on a channel nobody reads again, and the second request would hang until the
// process died rather than answering.
func (l *Listener) callback(state string, codes chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		if query.Get("state") != state {
			l.refuse(w, "That is not this login",
				"This callback does not belong to the login that is waiting.")
			return
		}
		code := query.Get("code")
		if code == "" {
			l.refuse(w, "No login code",
				"This callback carries no login code.")
			return
		}
		l.accept(w)
		select {
		case codes <- code:
		default:
		}
	}
}
