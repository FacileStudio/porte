package devicelogin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fake is Registre and the app on one local server. Token answers are played
// in order, and the last one repeats.
type fake struct {
	t        *testing.T
	server   *httptest.Server
	answers  []string
	exchange int
	interval int

	mu       sync.Mutex
	polls    []time.Time
	accessed string
}

// newFake starts a fake whose token endpoint plays answers and whose exchange
// route answers with status exchange.
func newFake(t *testing.T, exchange int, answers ...string) *fake {
	t.Helper()
	f := &fake{t: t, answers: answers, exchange: exchange, interval: 1}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("POST /device_authorization", f.authorize)
	mux.HandleFunc("POST /oauth/token", f.token)
	mux.HandleFunc("POST /api/auth/oidc/device/exchange", f.trade)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fake) discovery(w http.ResponseWriter, _ *http.Request) {
	_, _ = fmt.Fprintf(w, `{"device_authorization_endpoint":%q,"token_endpoint":%q,"grant_types_supported":[%q]}`,
		f.server.URL+"/device_authorization", f.server.URL+"/oauth/token", GrantType)
}

func (f *fake) authorize(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("client_id") != DefaultClientID || r.FormValue("scope") != DefaultScope {
		f.t.Errorf("authorize got client_id=%q scope=%q", r.FormValue("client_id"), r.FormValue("scope"))
	}
	_, _ = fmt.Fprintf(w, `{"device_code":"dev","user_code":"XTBG-LDJH","verification_uri":%q,`+
		`"verification_uri_complete":%q,"interval":%d,"expires_in":30}`,
		f.server.URL+"/device", f.server.URL+"/device?user_code=XTBG-LDJH", f.interval)
}

func (f *fake) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.polls = append(f.polls, time.Now())
	answer := f.answers[min(len(f.polls), len(f.answers))-1]
	f.mu.Unlock()
	if r.FormValue("grant_type") != GrantType || r.FormValue("device_code") != "dev" {
		f.t.Errorf("poll got grant_type=%q device_code=%q", r.FormValue("grant_type"), r.FormValue("device_code"))
	}
	if answer == "ok" {
		_, _ = w.Write([]byte(`{"access_token":"registre-token","token_type":"Bearer"}`))
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, answer)
}

func (f *fake) trade(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.AccessToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.accessed = body.AccessToken
	f.mu.Unlock()
	w.WriteHeader(f.exchange)
	_, _ = w.Write([]byte(`{"user_id":"42","token":"app-session"}`))
}

// endpoints is the fake's discovery result without a round trip.
func (f *fake) endpoints() Endpoints {
	return Endpoints{DeviceAuthorization: f.server.URL + "/device_authorization", Token: f.server.URL + "/oauth/token"}
}

// fast is a clock that never makes a test wait on RFC 8628's real seconds.
func fast() *schedule {
	return &schedule{interval: time.Millisecond, step: 20 * time.Millisecond, deadline: time.Now().Add(5 * time.Second)}
}

// seen reads what the fake recorded, under its lock, so the race detector
// sees the handler's writes ordered before the test's reads.
func (f *fake) seen() ([]time.Time, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.polls...), f.accessed
}
