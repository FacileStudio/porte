package handoff_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/internal/handoff"
)

// The page ends in a script block, and html/template's contextual escaping is
// strict inside one: a construct its JavaScript lexer cannot follow makes
// Execute fail at run time rather than at compile time, which would turn every
// CLI login into a blank page in production and nothing in a build log. This is
// the check that the markup still parses and still executes.
func TestTheCodePageRendersWithItsScriptIntact(t *testing.T) {
	recorder := httptest.NewRecorder()
	handoff.Write(recorder, http.StatusOK, handoff.Page{
		AppName: "Courrier",
		LogoURL: "https://courrier.facile.studio/logo.svg",
		Heading: "Signed in",
		Body:    "Paste this code into your terminal.",
		Hint:    "The code is valid for 60 seconds and works once.",
		Code:    "abc-DEF_123",
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	page := recorder.Body.String()
	for _, want := range []string{
		`<output id="c">abc-DEF_123</output>`,
		`<img src="https://courrier.facile.studio/logo.svg"`,
		"navigator.clipboard.writeText",
		"</script>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing %q:\n%s", want, page)
		}
	}
}

// A page with no code carries no copy button and no script to drive one, which
// is every page a CLI's loopback listener draws.
func TestAPageWithNoCodeCarriesNoScript(t *testing.T) {
	recorder := httptest.NewRecorder()
	handoff.Write(recorder, http.StatusBadRequest, handoff.Page{
		AppName: "Courrier",
		Heading: "That is not this login",
		Body:    "This callback does not belong to the login that is waiting.",
		Hint:    "The login started in your terminal is still waiting.",
		Warn:    true,
	})

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want the caller's 400", recorder.Code)
	}
	page := recorder.Body.String()
	if strings.Contains(page, "<script") || strings.Contains(page, "<button") {
		t.Errorf("a page with no code still ships the copy button:\n%s", page)
	}
	if strings.Contains(page, "<img") {
		t.Errorf("an empty LogoURL still drew an image:\n%s", page)
	}
	if !strings.Contains(page, `<p class="warn">`) {
		t.Errorf("a refusal is not marked as one:\n%s", page)
	}
}

// AppName reaches this template from configuration and LogoURL from a URL
// nobody here validates, so both are attacker-shaped in the one deployment
// where an operator pasted the wrong thing. html/template is what stops either
// from closing the script block or the attribute around it, and this is the
// test that says so rather than assuming it.
func TestHostileValuesAreEscapedRatherThanExecuted(t *testing.T) {
	recorder := httptest.NewRecorder()
	handoff.Write(recorder, http.StatusOK, handoff.Page{
		AppName: `</script><script>alert(1)</script>`,
		LogoURL: `javascript:alert(1)`,
		Heading: "Signed in",
		Body:    `" onload="alert(1)`,
		Code:    `</output><script>alert(1)</script>`,
	})

	page := recorder.Body.String()
	if strings.Contains(page, "alert(1)</script>") {
		t.Errorf("a value closed the script block:\n%s", page)
	}
	if strings.Contains(page, `<script>alert(1)`) {
		t.Errorf("a value opened a script block:\n%s", page)
	}
	if strings.Contains(page, `src="javascript:`) {
		t.Errorf("a javascript: URL survived into the src attribute:\n%s", page)
	}
	if strings.Contains(page, `onload="alert(1)`) {
		t.Errorf("a value escaped its attribute:\n%s", page)
	}
}
