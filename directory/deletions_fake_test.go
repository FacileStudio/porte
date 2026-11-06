package directory

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type registre struct {
	t       *testing.T
	key     *rsa.PrivateKey
	server  *httptest.Server
	mu      sync.Mutex
	list    []Deleted
	sinces  []time.Time
	clients string
}

func newRegistre(t *testing.T) *registre {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r := &registre{t: t, key: key, clients: "app"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": r.server.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1", "n": n, "e": e}}})
	})
	mux.HandleFunc("/api/directory/deletions", r.deletions)
	r.server = httptest.NewServer(mux)
	t.Cleanup(r.server.Close)
	return r
}

func (r *registre) deletions(w http.ResponseWriter, req *http.Request) {
	if id, secret, ok := req.BasicAuth(); !ok || id != "app" || secret != "s3cret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	since, err := time.Parse(time.RFC3339, req.URL.Query().Get("since"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinces = append(r.sinces, since)
	out := []Deleted{}
	for _, d := range r.list {
		if d.DeletedAt.After(since) {
			out = append(out, d)
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"deleted": out})
}

func (r *registre) delete(subject string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, Deleted{Subject: subject, DeletedAt: at})
}

type mutation func(header, claims map[string]any)

func (r *registre) notice(subject string, mutate ...mutation) string {
	now := time.Now()
	header := map[string]any{"alg": "RS256", "typ": "secevent+jwt", "kid": "k1"}
	claims := map[string]any{
		"iss": r.server.URL, "aud": []string{"app"}, "sub": subject, "jti": "j",
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"events": map[string]any{UserDeletedEvent: map[string]any{"erase_within_days": 30}},
	}
	for _, m := range mutate {
		m(header, claims)
	}
	return r.sign(header, claims)
}

func (r *registre) sign(header, claims map[string]any) string {
	encode := func(v any) string {
		data, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signing := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, digest[:])
	if err != nil {
		r.t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type memoryState struct {
	mu   sync.Mutex
	data []byte
}

func (m *memoryState) Load(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data, nil
}

func (m *memoryState) Save(_ context.Context, state []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), state...)
	return nil
}

type calls struct {
	mu      sync.Mutex
	erased  []string
	fail    map[string]bool
	porte   []string
	failEra bool
}

func (c *calls) callback(_ context.Context, provider, subject string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.erased = append(c.erased, provider+"|"+subject)
	if c.fail[subject] {
		return errors.New("app is down")
	}
	return nil
}

func (c *calls) erase(_ context.Context, _, subject string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failEra {
		return errors.New("db is down")
	}
	c.porte = append(c.porte, subject)
	return nil
}

func receiver(r *registre, c *calls, state StateStore) *Deletions {
	return &Deletions{
		Client:          Client{Issuer: r.server.URL, ClientID: "app", ClientSecret: "s3cret"},
		OnPersonDeleted: c.callback,
		Erase:           c.erase,
		State:           state,
	}
}

func push(d *Deletions, token string) int {
	request := httptest.NewRequest(http.MethodPost, DeletionsPath, strings.NewReader(token))
	request.Header.Set("Content-Type", "application/secevent+jwt")
	recorder := httptest.NewRecorder()
	d.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}
