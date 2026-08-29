package loopback

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// LoginURL builds the address the browser starts the flow at, from an origin
// such as https://courrier.facile.studio and the path the app mounts porte
// under. Every suite app mounts at "/api" today, and "" is the app that serves
// its API from the root.
//
// The mount point is a parameter because it is the app's decision and not
// porte's: porte's routes are relative to whatever router carries them. Three
// CLIs hardcoded "/api" and the first app to move would have broken all three,
// silently and in the worst way, because a login URL with the wrong path is not
// an error. The browser completes an ordinary web login, the user sees their
// dashboard, and this listener waits three minutes for a redirect nobody is
// going to send.
//
// porte reads exactly the parameters flow, port and cli_state and answers on
// /auth/oidc. Rename any of the four and you get that same silent failure.
func (l *Listener) LoginURL(origin, mount, state string) string {
	query := url.Values{}
	query.Set("flow", "cli")
	query.Set("port", strconv.Itoa(l.port))
	query.Set("cli_state", state)

	target := strings.TrimRight(origin, "/")
	if at := strings.Trim(mount, "/"); at != "" {
		target += "/" + at
	}
	return target + "/auth/oidc?" + query.Encode()
}

// RandomState returns a fresh nonce for one login. porte echoes it back on the
// redirect, which is what proves the callback belongs to this login rather than
// to any page that guessed the port.
//
// Sixteen random bytes are encoded base64url without padding, which is 22
// characters drawn from [A-Za-z0-9-_], inside porte's 128-character bound and
// its permitted alphabet. A shorter or differently encoded nonce is refused by
// the server before the browser ever leaves, so this is not a free choice.
func RandomState() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("loopback: cannot draw a login nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce), nil
}

// OpenBrowser hands the URL to the operating system's default browser. It is
// best effort by design: false means no browser could be launched, which is an
// ssh session or a container rather than a failure, and the caller prints the
// URL for the user to open by hand.
func OpenBrowser(rawURL string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", rawURL)
	case "windows":
		command = exec.Command("cmd", "/C", "start", "", rawURL)
	default:
		command = exec.Command("xdg-open", rawURL)
	}
	return command.Start() == nil
}
