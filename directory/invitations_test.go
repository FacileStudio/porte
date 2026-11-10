package directory

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type invitationsFake struct {
	t      *testing.T
	server *httptest.Server
	body   func(origin string) string
	delay  time.Duration
}

func newInvitationsFake(t *testing.T, body func(origin string) string) *invitationsFake {
	t.Helper()
	fake := &invitationsFake{t: t, body: body}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *invitationsFake) serve(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != "nuage" || secret != "s3cret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Path != InvitationsPath || r.URL.Query().Get("sub") != "sub-1&x" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	select {
	case <-time.After(f.delay):
	case <-r.Context().Done():
		return
	}
	_, _ = w.Write([]byte(f.body(f.server.URL)))
}

func (f *invitationsFake) client() Client {
	return Client{Issuer: f.server.URL + "/", ClientID: "nuage", ClientSecret: "s3cret", HTTP: f.server.Client()}
}

func oneInvitation(origin string) string {
	return `{"count":1,"invitations":[{"id":"a","space_name":"EpiKodi","role":"member",` +
		`"invited_by":"Noah","expires_at":"2026-11-24T10:00:00Z","url":"` + origin + `/invitations/a"}]}`
}

// TestInvitationsSendsBasicAuthAndDecodes: the subject is escaped, the app's
// pair is sent, and a well-formed answer decodes.
func TestInvitationsSendsBasicAuthAndDecodes(t *testing.T) {
	fake := newInvitationsFake(t, oneInvitation)
	got, err := fake.client().Invitations(context.Background(), "sub-1&x")
	if err != nil || len(got) != 1 || got[0].SpaceName != "EpiKodi" || got[0].URL != fake.server.URL+"/invitations/a" {
		t.Fatalf("Invitations = %+v, %v", got, err)
	}
	wrong := fake.client()
	wrong.ClientSecret = "nope"
	if _, err := wrong.Invitations(context.Background(), "sub-1&x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a refused pair = %v, want ErrUnavailable", err)
	}
}

// TestInvitationsRejectsBadAnswers: anything but a consistent answer whose
// links stay on the issuer is ErrUnavailable.
func TestInvitationsRejectsBadAnswers(t *testing.T) {
	cases := map[string]func(string) string{
		"malformed":       func(string) string { return `{"count":` },
		"no count":        func(string) string { return `{"invitations":[]}` },
		"count mismatch":  func(string) string { return `{"count":2,"invitations":[]}` },
		"trailing data":   func(o string) string { return oneInvitation(o) + `{}` },
		"foreign link":    func(string) string { return oneInvitation("https://evil.test") },
		"javascript link": func(string) string { return oneInvitation("javascript:alert(1)//") },
		"no id":           func(o string) string { return strings.Replace(oneInvitation(o), `"id":"a"`, `"id":""`, 1) },
		"oversized": func(o string) string {
			return `{"count":0,"invitations":[],"x":"` + strings.Repeat("a", MaxInvitationsBytes) + `"}`
		},
	}
	for name, body := range cases {
		fake := newInvitationsFake(t, body)
		if _, err := fake.client().Invitations(context.Background(), "sub-1&x"); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: err = %v, want ErrUnavailable", name, err)
		}
	}
}

// TestInvitationsWithoutASubjectSendsNothing: an empty subject never reaches
// Registre.
func TestInvitationsWithoutASubjectSendsNothing(t *testing.T) {
	client := Client{Issuer: "http://127.0.0.1:1", HTTP: &http.Client{Transport: failingTransport{t}}}
	if _, err := client.Invitations(context.Background(), ""); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("an empty subject = %v, want ErrNoSubject", err)
	}
}

// TestInvitationsIsBoundedInTime: a Registre that never answers costs at most
// InvitationsTimeout, even under a context with no deadline.
func TestInvitationsIsBoundedInTime(t *testing.T) {
	fake := newInvitationsFake(t, oneInvitation)
	fake.delay = time.Minute
	started := time.Now()
	_, err := fake.client().Invitations(context.Background(), "sub-1&x")
	if !errors.Is(err, ErrUnavailable) || time.Since(started) > InvitationsTimeout+time.Second {
		t.Fatalf("a stalled Registre = %v after %s", err, time.Since(started))
	}
}

type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("a request was sent")
	return nil, errors.New("no network")
}
