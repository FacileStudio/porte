package loopback

import (
	"net/http"
	"strings"

	"github.com/FacileStudio/porte/internal/handoff"
)

// The last line of each page. A success sends the user back to the terminal; a
// refusal must not, because a refused callback does not end the login and the
// terminal really is still waiting. Telling the user otherwise sends them to
// restart something that is working.
const (
	hintClose   = "You can close this tab and go back to your terminal."
	hintWaiting = "The login started in your terminal is still waiting."
)

// fallbackName is what the pages say when a caller left AppName empty. It
// matches porte.DefaultAppName by hand rather than by import, because this
// package does not import the contract and a CLI must not compile it to draw
// a page.
const fallbackName = "Sign-in"

// accept draws the page a user sees once the code has landed. It is the same
// markup porte's own code page uses, so a login that ends in a browser looks
// the same whether the CLI was listening or the user is about to paste.
func (l *Listener) accept(w http.ResponseWriter) {
	handoff.Write(w, http.StatusOK, l.page("Signed in", l.signedIn(), hintClose, false))
}

// refuse answers a callback this listener will not accept.
//
// It renders the page rather than http.Error, which sends text/plain: the
// reader is a human in a browser tab who has just been through a login, and a
// bare status line there reads as a broken app rather than as a refused
// request. The status is still 400, and the login is still open.
func (l *Listener) refuse(w http.ResponseWriter, heading, body string) {
	handoff.Write(w, http.StatusBadRequest, l.page(heading, body, hintWaiting, true))
}

// page fills in what every page from this listener shares.
//
// There is no logo, deliberately. This server is a CLI binary answering on
// 127.0.0.1, and a page that fetches an image over the network is a page that
// hangs on the laptop whose network is the thing the user is trying to fix.
func (l *Listener) page(heading, body, hint string, warn bool) handoff.Page {
	name := strings.TrimSpace(l.AppName)
	if name == "" {
		name = fallbackName
	}
	return handoff.Page{
		AppName: name,
		Heading: heading,
		Body:    body,
		Hint:    hint,
		Warn:    warn,
	}
}

// signedIn is the success page's sentence. A CLI that set no name gets one that
// still reads: "Sign-in has your login" would be worse than a page that names
// nobody, and this is the one line where the fallback shows.
func (l *Listener) signedIn() string {
	if name := strings.TrimSpace(l.AppName); name != "" {
		return name + " has your login."
	}
	return "Your login is complete."
}
