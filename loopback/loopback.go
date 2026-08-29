// Package loopback is the listener half of porte's CLI login: it binds a
// loopback port, builds the URL the browser starts the login at, and waits for
// porte to redirect back with a one-time code.
//
// It owns only the part three CLIs each got subtly different. Trading the code
// for a session token, storing that token, and everything the CLI does
// afterwards stay with the CLI: this package holds no credentials, writes no
// files and knows nothing about the app it signs into beyond its origin and the
// path porte is mounted at.
//
// The security properties are the whole reason it is shared. A callback whose
// state does not match is refused and the login keeps waiting, because ending
// it would let any page the user has open close a login it did not start, and
// accepting it would let that page hand this CLI a session that is not the
// user's. Both failures are silent, which is why they belong in one reviewed
// copy rather than three.
//
// Standard library only, on purpose, apart from porte's own stdlib-only
// packages. This is linked into every CLI in the suite, and a binary that opens
// a browser and waits on a socket must not compile go-oidc, oauth2, chi, pgx or
// tronc to do it.
package loopback

import (
	"errors"
	"fmt"
	"net"
)

// Listener is a bound loopback socket waiting for the login redirect. The port
// is taken before the login URL is built, so the URL can name a port that is
// already listening and nothing else can claim it in between.
type Listener struct {
	// AppName is the tool the pages name, "Courrier" or "Journal". By the
	// time a browser reaches 127.0.0.1 it has left the app's domain behind
	// and the address bar proves nothing, so the name on the page is all a
	// user has to tell this login from any other local process that asked
	// for one. Empty draws a page that reads correctly and names nobody,
	// which is worse than setting it and better than a page with a hole in
	// it.
	AppName string

	listener net.Listener
	port     int
}

// Listen binds 127.0.0.1 on an ephemeral port. The port is chosen by the kernel
// rather than fixed, so two shells can run a login at the same time without
// coordinating. The caller must Close the listener.
//
// The address is read back rather than assumed. A tcp listener always carries a
// *net.TCPAddr today, but a type assertion that turns out wrong panics inside a
// CLI's login instead of failing it, and there is no port to redirect to either
// way.
func Listen() (*Listener, error) {
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("loopback: cannot open the login listener: %w", err)
	}
	address, ok := socket.Addr().(*net.TCPAddr)
	if !ok {
		_ = socket.Close()
		return nil, fmt.Errorf("loopback: the login listener bound %s, which carries no port to redirect to", socket.Addr())
	}
	return &Listener{listener: socket, port: address.Port}, nil
}

// Port reports the loopback port the browser will be redirected back to.
func (l *Listener) Port() int {
	return l.port
}

// Close releases the loopback port. It is safe to call after WaitForCode, which
// closes the socket itself as it shuts the callback server down, so a deferred
// Close does not become an error on the successful path.
func (l *Listener) Close() error {
	if err := l.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
