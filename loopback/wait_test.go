package loopback_test

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/porte/loopback"
)

// The happy path. porte redirects the browser to 127.0.0.1 carrying the code
// and the nonce it was handed, and the listener gives the code back.
func TestACallbackWithTheMatchingStateReturnsTheCode(t *testing.T) {
	base, done := serve(t, "Courrier", "nonce-1")

	response, _ := callback(t, base+"/?state=nonce-1&code=one-time-code")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the callback answered %d, want 200", response.StatusCode)
	}
	if code, err := settle(t, done); err != nil || code != "one-time-code" {
		t.Fatalf("WaitForCode = %q, %v, want the code porte sent", code, err)
	}
}

// Any page the user has open can guess an ephemeral port and hit this listener
// with a code of its own choosing. Refusing a mismatched nonce is half the
// rule; the login staying open is the other half, because otherwise that same
// page can end every login it did not start.
func TestAMismatchedStateIsRefusedAndTheLoginStaysOpen(t *testing.T) {
	base, done := serve(t, "Courrier", "nonce-1")

	response, page := callback(t, base+"/?state=guessed&code=attacker-code")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("a mismatched nonce answered %d, want 400", response.StatusCode)
	}
	if strings.Contains(page, "attacker-code") {
		t.Error("the refusal page echoes the code it refused")
	}
	if !strings.Contains(page, "still waiting") {
		t.Errorf("the refusal page does not say the login is still open:\n%s", page)
	}

	callback(t, base+"/?state=nonce-1&code=real-code")
	if code, err := settle(t, done); err != nil || code != "real-code" {
		t.Fatalf("WaitForCode = %q, %v, want the real callback to still be accepted", code, err)
	}
}

// A browser asks for /favicon.ico without being told to, and some open the
// bare callback path first. Ending the login over either produces a failure
// with nothing in it a user could act on.
func TestARequestWithNoCodeDoesNotEndTheLogin(t *testing.T) {
	base, done := serve(t, "Courrier", "nonce-1")

	if response, _ := callback(t, base+"/favicon.ico"); response.StatusCode != http.StatusNotFound {
		t.Errorf("a favicon request answered %d, want 404", response.StatusCode)
	}
	if response, _ := callback(t, base+"/?state=nonce-1"); response.StatusCode != http.StatusBadRequest {
		t.Errorf("a callback with no code answered %d, want 400", response.StatusCode)
	}

	callback(t, base+"/?state=nonce-1&code=real-code")
	if code, err := settle(t, done); err != nil || code != "real-code" {
		t.Fatalf("WaitForCode = %q, %v, want the login to have survived both", code, err)
	}
}

// This page is the last thing a user sees before going back to the terminal.
// It has to be a page rather than a status line, and it has to say whose login
// it just finished: the address bar says 127.0.0.1 and proves nothing.
func TestTheSuccessPageIsHTMLAndNamesTheTool(t *testing.T) {
	base, done := serve(t, "Courrier", "nonce-1")

	response, page := callback(t, base+"/?state=nonce-1&code=one-time-code")
	if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if !strings.Contains(page, "Courrier has your login.") {
		t.Errorf("the success page does not name the tool:\n%s", page)
	}
	if !strings.Contains(page, "Signed in") {
		t.Errorf("the success page carries no heading:\n%s", page)
	}
	if strings.Contains(page, "<img") {
		t.Error("the page fetches an image, which a CLI page on 127.0.0.1 must never need")
	}
	if strings.Contains(page, "one-time-code") {
		t.Error("the page prints the code, which the terminal already has and a shoulder does not need")
	}
	settle(t, done)
}

// serve binds a listener and runs WaitForCode behind it, returning the loopback
// base URL and the channel its outcome arrives on. Every property under test
// here is something the handler does with a live request, so a fake server
// would only test the fake.
func serve(t *testing.T, appName, state string) (string, <-chan outcome) {
	t.Helper()
	listener, err := loopback.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	listener.AppName = appName
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan outcome, 1)
	go func() {
		code, err := listener.WaitForCode(context.Background(), state)
		done <- outcome{code: code, err: err}
	}()
	return "http://127.0.0.1:" + strconv.Itoa(listener.Port()), done
}

// outcome is what one WaitForCode call produced.
type outcome struct {
	code string
	err  error
}

// settle waits for WaitForCode to return. The bound is generous and still far
// under the three minute timeout, so a test that reaches it has hung rather
// than timed out.
func settle(t *testing.T, done <-chan outcome) (string, error) {
	t.Helper()
	select {
	case got := <-done:
		return got.code, got.err
	case <-time.After(10 * time.Second):
		t.Fatal("WaitForCode never returned")
		return "", nil
	}
}

// callback performs one browser navigation against the listener. Keep-alives
// are off because every request here is a navigation and a pooled connection
// would outlive the server it was made to.
func callback(t *testing.T, rawURL string) (*http.Response, string) {
	t.Helper()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	response, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	return response, string(body)
}
