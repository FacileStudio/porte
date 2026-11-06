package directory

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// UserDeletedEvent is the key Registre's deletion notice carries in `events`.
const UserDeletedEvent = "https://schemas.facile.studio/event/user-deleted"

const (
	secEventType  = "secevent+jwt"
	maxNoticeSize = 16 << 10
	clockLeeway   = time.Minute
	maxNoticeLife = time.Hour
)

var errBadNotice = errors.New("directory: invalid deletion notice")

type noticeClaims struct {
	Issuer   string         `json:"iss"`
	Audience audience       `json:"aud"`
	Subject  string         `json:"sub"`
	IssuedAt int64          `json:"iat"`
	Expires  int64          `json:"exp"`
	Events   map[string]any `json:"events"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(a))
}

// Handler accepts Registre's signed user.deleted push on DeletionsPath. It
// answers 400 to anything that does not verify, 503 when the issuer's keys cannot be fetched, 500 when erasing failed so
// Registre retries, and 202 once the person is erased or was already.
//
// A notice verifies only when its JWS typ is secevent+jwt, it is RS256 signed
// by a key in the issuer's JWKS, iss is Client.Issuer, aud holds
// Client.ClientID, it is inside its time window and names the user-deleted
// event. A replay is harmless because handling is keyed on the subject: a
// subject already erased reaches the callback no more.
func (d *Deletions) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw, err := readAll(r.Body, maxNoticeSize)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err := d.verify(r.Context(), strings.TrimSpace(string(raw)), time.Now())
		if errors.Is(err, ErrUnavailable) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		err = d.handle(r.Context(), claims.Subject, time.Time{})
		d.mu.Unlock()
		if err != nil {
			d.logger().Warn("directory: erase from a pushed notice failed", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}

// verify checks a compact JWS against everything the Handler promises.
func (d *Deletions) verify(ctx context.Context, token string, now time.Time) (noticeClaims, error) {
	var claims noticeClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errBadNotice
	}
	var header struct{ Alg, Typ, Kid string }
	if decodePart(parts[0], &header) != nil || header.Alg != "RS256" || header.Typ != secEventType {
		return claims, errBadNotice
	}
	key, err := d.keys.lookup(ctx, d.Client, header.Kid)
	if errors.Is(err, ErrUnavailable) {
		return claims, err
	}
	if err != nil || !validSignature(key, parts) {
		return claims, errBadNotice
	}
	if decodePart(parts[1], &claims) != nil || !d.acceptable(claims, now) {
		return claims, errBadNotice
	}
	return claims, nil
}

// acceptable checks the claims once the signature holds.
func (d *Deletions) acceptable(c noticeClaims, now time.Time) bool {
	_, event := c.Events[UserDeletedEvent]
	issued, expires := time.Unix(c.IssuedAt, 0), time.Unix(c.Expires, 0)
	return event && c.Subject != "" &&
		trimIssuer(c.Issuer) == trimIssuer(d.Client.Issuer) &&
		hasAudience(c.Audience, d.Client.ClientID) &&
		expires.After(now.Add(-clockLeeway)) && !issued.After(now.Add(clockLeeway)) &&
		expires.Sub(issued) <= maxNoticeLife
}

func hasAudience(list audience, clientID string) bool {
	for _, a := range list {
		if a == clientID {
			return true
		}
	}
	return false
}

func decodePart(part string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func validSignature(key *rsa.PublicKey, parts []string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
}
