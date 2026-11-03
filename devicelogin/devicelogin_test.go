package devicelogin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// pending then slow_down then success: the token comes back, and the gap after
// slow_down grew by the step rather than staying at the interval.
func TestPollWaitsThroughPendingAndSlowDown(t *testing.T) {
	f := newFake(t, http.StatusOK, "authorization_pending", "slow_down", "ok")

	token, err := f.endpoints().poll(context.Background(), DefaultClientID, Authorization{DeviceCode: "dev"}, fast())
	if err != nil || token != "registre-token" {
		t.Fatalf("poll = %q, %v, want the provider's token", token, err)
	}
	polls, _ := f.seen()
	if len(polls) != 3 {
		t.Fatalf("polls = %d, want 3", len(polls))
	}
	if gap := polls[2].Sub(polls[1]); gap < 20*time.Millisecond {
		t.Fatalf("the poll after slow_down came %s later, want at least the 20ms step", gap)
	}
}

// The four RFC outcomes stay distinct, because each sends the user somewhere
// different.
func TestPollStopsOnDeniedAndExpired(t *testing.T) {
	for answer, want := range map[string]error{"access_denied": ErrDenied, "expired_token": ErrExpired} {
		t.Run(answer, func(t *testing.T) {
			f := newFake(t, http.StatusOK, answer)
			_, err := f.endpoints().poll(context.Background(), DefaultClientID, Authorization{DeviceCode: "dev"}, fast())
			if !errors.Is(err, want) {
				t.Fatalf("poll = %v, want %v", err, want)
			}
		})
	}
}

// Running out the clock is an expiry too, and Ctrl-C is not an error of ours.
func TestPollEndsOnDeadlineAndCancellation(t *testing.T) {
	f := newFake(t, http.StatusOK, "authorization_pending")
	clock := fast()
	clock.deadline = time.Now().Add(30 * time.Millisecond)
	if _, err := f.endpoints().poll(context.Background(), DefaultClientID, Authorization{DeviceCode: "dev"}, clock); !errors.Is(err, ErrExpired) {
		t.Fatalf("poll past the deadline = %v, want ErrExpired", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.endpoints().poll(ctx, DefaultClientID, Authorization{DeviceCode: "dev"}, fast()); !errors.Is(err, context.Canceled) {
		t.Fatalf("poll with a cancelled context = %v, want context.Canceled", err)
	}
}

// 404 and 401 are the two answers a CLI acts on, and 200 carries the session.
func TestExchangeMapsTheAppsAnswers(t *testing.T) {
	cases := map[int]error{http.StatusNotFound: ErrExchangeNotMounted, http.StatusUnauthorized: ErrAccountNotLinked, http.StatusOK: nil}
	for status, want := range cases {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newFake(t, status, "ok")
			session, err := Exchange(context.Background(), f.server.URL+"/", "api/", "registre-token")
			if !errors.Is(err, want) {
				t.Fatalf("Exchange = %v, want %v", err, want)
			}
			if want == nil && (session != Session{Token: "app-session", UserID: "42"}) {
				t.Fatalf("Exchange = %+v, want the app's session", session)
			}
		})
	}
}

// Mounted reads 404 as absent and porte's 400 to an empty body as present.
func TestMountedProbesWithAnEmptyBody(t *testing.T) {
	f := newFake(t, http.StatusOK, "ok")
	if mounted, err := Mounted(context.Background(), f.server.URL, "/api"); err != nil || !mounted {
		t.Fatalf("Mounted on the real route = %v, %v, want true", mounted, err)
	}
	if mounted, err := Mounted(context.Background(), f.server.URL, "/elsewhere"); err != nil || mounted {
		t.Fatalf("Mounted on a missing route = %v, %v, want false", mounted, err)
	}
}

// The whole flow: one line naming the complete link and the code, the browser
// handed the same link, and the provider's token traded for the app session.
func TestLoginRunsTheWholeFlow(t *testing.T) {
	f := newFake(t, http.StatusOK, "ok")
	var out bytes.Buffer
	var opened string

	session, err := Login(context.Background(), Options{
		AppOrigin: f.server.URL, Mount: "/api", Issuer: f.server.URL, Out: &out,
		OpenBrowser: func(link string) bool { opened = link; return false },
	})
	if _, accessed := f.seen(); err != nil || session.Token != "app-session" || accessed != "registre-token" {
		t.Fatalf("Login = %+v, %v, exchanged %q", session, err, accessed)
	}
	link := f.server.URL + "/device?user_code=XTBG-LDJH"
	if opened != link || strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), link) {
		t.Fatalf("printed %q and opened %q, want one line with %s", out.String(), opened, link)
	}
}

// An app without the exchange is found out before the user is asked anything.
func TestLoginFallsBackBeforePrinting(t *testing.T) {
	f := newFake(t, http.StatusOK, "ok")
	var out bytes.Buffer
	_, err := Login(context.Background(), Options{AppOrigin: f.server.URL, Mount: "/v2", Issuer: f.server.URL, Out: &out})
	polls, _ := f.seen()
	if !errors.Is(err, ErrExchangeNotMounted) || out.Len() != 0 || len(polls) != 0 {
		t.Fatalf("Login = %v after printing %q and %d polls, want ErrExchangeNotMounted and silence", err, out.String(), len(polls))
	}
}

// Everything the grant trusts comes from discovery, so plaintext is refused
// anywhere but loopback, and a document without the grant is ErrNoDeviceGrant.
func TestDiscoverRefusesWhatItShouldNotTrust(t *testing.T) {
	if _, err := Discover(context.Background(), "http://sso.example.test"); err == nil {
		t.Fatal("Discover accepted a plaintext issuer")
	}
	doc := map[string]any{"device_authorization_endpoint": "https://x/d", "token_endpoint": "https://x/t",
		"grant_types_supported": []any{"authorization_code"}}
	if _, err := endpointsFrom(doc); !errors.Is(err, ErrNoDeviceGrant) {
		t.Fatalf("endpointsFrom without the grant = %v, want ErrNoDeviceGrant", err)
	}
	f := newFake(t, http.StatusOK, "ok")
	if got, err := Discover(context.Background(), f.server.URL+"/"); err != nil || got != f.endpoints() {
		t.Fatalf("Discover = %+v, %v, want the fake's endpoints", got, err)
	}
}

// The package doc's last paragraph is a constraint, held up the same way
// loopback holds up its own: an import added here is added to every CLI.
func TestDeviceloginDependsOnTheStandardLibraryAlone(t *testing.T) {
	tool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool on PATH to list dependencies with")
	}
	listed, err := exec.Command(tool, "list", "-deps", "github.com/FacileStudio/porte/devicelogin").Output()
	if err != nil {
		t.Skipf("go list -deps did not run, so the constraint went unchecked: %v", err)
	}
	for _, dependency := range strings.Fields(string(listed)) {
		first, _, _ := strings.Cut(dependency, "/")
		if strings.Contains(first, ".") && !strings.HasPrefix(dependency, "github.com/FacileStudio/porte/") {
			t.Errorf("porte/devicelogin pulls in %s, which no CLI should have to compile", dependency)
		}
	}
}
