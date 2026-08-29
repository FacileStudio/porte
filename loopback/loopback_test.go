package loopback_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/loopback"
)

// The package doc's last paragraph is a constraint, and this is what holds it
// up. Every CLI in the suite links this package, so an import added here is an
// import added to five binaries. The one that would look harmless in review is
// the tronc httpjson helper, where a single call to write a JSON error response
// drags tronc into every one of them and nothing else in the repo notices.
//
// porte's own packages pass, because the stdlib-only rule is the one they live
// under too. If one of them ever breaks it, whatever it pulled in appears in
// this same list and fails here.
//
// It skips rather than fails when the go tool cannot list: a tool whose GOROOT
// disagrees with the module cannot load a package at all, which reads like a
// broken dependency and is not. scripts/check.sh skips its lint pass for the
// same reason.
func TestLoopbackDependsOnTheStandardLibraryAlone(t *testing.T) {
	tool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool on PATH to list dependencies with")
	}
	listed, err := exec.Command(tool, "list", "-deps", "github.com/FacileStudio/porte/loopback").Output()
	if err != nil {
		t.Skipf("go list -deps did not run, so the constraint went unchecked: %v", err)
	}
	for _, dependency := range strings.Fields(string(listed)) {
		if standardLibrary(dependency) || strings.HasPrefix(dependency, "github.com/FacileStudio/porte/") {
			continue
		}
		t.Errorf("porte/loopback pulls in %s, which no CLI should have to compile", dependency)
	}
}

// standardLibrary applies the go tool's own test: a package path whose first
// element carries a dot is a module path, and everything else ships with Go.
func standardLibrary(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// Close is documented as safe after WaitForCode, which shuts the callback
// server down and closes the socket itself. A deferred Close is the obvious way
// to write the caller, and it must not turn a completed login into an error.
func TestCloseIsSafeAfterTheServerAlreadyClosedTheSocket(t *testing.T) {
	listener, err := loopback.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if listener.Port() == 0 {
		t.Fatal("Listen returned no port, so no login URL can name one")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close on an already closed socket = %v, want nil", err)
	}
}
