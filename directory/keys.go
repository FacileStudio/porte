package directory

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	jwksRefetchGap = time.Minute
	maxKeyDocument = 1 << 20
)

var errUnknownKey = errors.New("directory: no signing key with that kid")

// keySet is the issuer's RSA signing keys, found through its discovery
// document and refetched when a token names a kid it does not hold, at most
// once a minute so a forged kid cannot make the app hammer Registre.
type keySet struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// lookup returns the key for kid, refreshing the set when kid is new.
func (k *keySet) lookup(ctx context.Context, c Client, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	if time.Since(k.fetched) < jwksRefetchGap {
		return nil, errUnknownKey
	}
	keys, err := fetchKeys(ctx, c)
	k.fetched = time.Now()
	if err != nil {
		return nil, err
	}
	k.keys = keys
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, errUnknownKey
}

// getJSON reads a small unauthenticated JSON document.
func getJSON(ctx context.Context, c Client, target string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrUnavailable, target, response.StatusCode)
	}
	data, err := readAll(response.Body, maxKeyDocument)
	if err != nil {
		return fmt.Errorf("%w: read %s: %w", ErrUnavailable, target, err)
	}
	return json.Unmarshal(data, into)
}

// fetchKeys reads the issuer's JWKS through its discovery document.
func fetchKeys(ctx context.Context, c Client) (map[string]*rsa.PublicKey, error) {
	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, c, trimIssuer(c.Issuer)+"/.well-known/openid-configuration", &discovery); err != nil {
		return nil, err
	}
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, c, discovery.JWKSURI, &document); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range document.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") {
			continue
		}
		if key := rsaKey(jwk.N, jwk.E); key != nil {
			keys[jwk.Kid] = key
		}
	}
	return keys, nil
}

// rsaKey builds a public key from base64url modulus and exponent, or nil.
func rsaKey(n, e string) *rsa.PublicKey {
	modulus, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(n, "="))
	if err != nil {
		return nil
	}
	exponent, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(e, "="))
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}
}
