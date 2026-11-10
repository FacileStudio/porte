package conformance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/FacileStudio/porte/pg"
)

const (
	sealPrefix = "pv1:"
	sealInfo   = "porte/pg token sealing v1"
	sealAAD    = "porte/pg identity token"
)

var (
	newestSecret = strings.Repeat("11", 32)
	olderSecret  = strings.Repeat("22", 32)
	fixedNonce   = []byte("conformance!")
)

func sealFixed(t *testing.T, secretHex, plain string, aad string) string {
	t.Helper()
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatalf("decoding a secret: %v", err)
	}
	key, err := hkdf.Key(sha256.New, secret, nil, sealInfo, 32)
	if err != nil {
		t.Fatalf("deriving a key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("building the cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("building the cipher: %v", err)
	}
	sealed := aead.Seal(append([]byte(nil), fixedNonce...), fixedNonce, []byte(plain), []byte(aad))
	return sealPrefix + base64.RawURLEncoding.EncodeToString(sealed)
}

func openCase(t *testing.T, name, spec, stored string) testCase {
	t.Helper()
	sealer, err := pg.ParseTokenSealer(spec)
	if err != nil {
		t.Fatalf("parsing %q: %v", spec, err)
	}
	want := map[string]any{"plain": "", "error": nil}
	plain, err := sealer.Open(stored)
	if err != nil {
		want["error"] = "unreadable"
	} else {
		want["plain"] = plain
	}
	return testCase{Name: name, Input: map[string]string{"kind": "open", "spec": spec, "stored": stored}, Want: want}
}

func openCases(t *testing.T) []testCase {
	sealed := sealFixed(t, newestSecret, "refresh-token-1", sealAAD)
	older := sealFixed(t, olderSecret, "refresh-token-2", sealAAD)
	base64Spec := base64.StdEncoding.EncodeToString(mustHex(t, newestSecret))
	return []testCase{
		openCase(t, "opens with the newest secret", newestSecret, sealed),
		openCase(t, "opens with a base64 secret", base64Spec, sealed),
		openCase(t, "opens with an older secret", newestSecret+","+olderSecret, older),
		openCase(t, "plaintext passes through", newestSecret, "legacy-plain-token"),
		openCase(t, "plaintext passes through without a sealer", "", "legacy-plain-token"),
		openCase(t, "empty stays empty", newestSecret, ""),
		openCase(t, "wrong secret is unreadable", olderSecret, sealed),
		openCase(t, "no sealer cannot open a sealed value", "", sealed),
		openCase(t, "tampered ciphertext is unreadable", newestSecret, sealed[:len(sealed)-2]+"AA"),
		openCase(t, "wrong associated data is unreadable", newestSecret, sealFixed(t, newestSecret, "x", "other")),
		openCase(t, "bad base64 is unreadable", newestSecret, sealPrefix+"!!!"),
		openCase(t, "shorter than a nonce is unreadable", newestSecret, sealPrefix+"AAAA"),
	}
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("decoding %q: %v", text, err)
	}
	return decoded
}

func parseCases() []testCase {
	specs := [][2]string{
		{"empty spec turns sealing off", "  "},
		{"hex secret", newestSecret},
		{"two secrets, spaces trimmed", newestSecret + " , " + olderSecret},
		{"short hex secret is refused", strings.Repeat("11", 16)},
		{"base64 of 31 bytes is refused", base64.StdEncoding.EncodeToString(make([]byte, 31))},
		{"garbage is refused", "not-a-secret"},
		{"an empty entry is refused", newestSecret + ","},
	}
	cases := make([]testCase, 0, len(specs))
	for _, spec := range specs {
		sealer, err := pg.ParseTokenSealer(spec[1])
		cases = append(cases, testCase{
			Name:  spec[0],
			Input: map[string]string{"kind": "parse", "spec": spec[1]},
			Want:  map[string]bool{"ok": err == nil, "sealing": sealer != nil},
		})
	}
	return cases
}

func sealCase(t *testing.T, plain string) testCase {
	t.Helper()
	sealer, err := pg.ParseTokenSealer(newestSecret)
	if err != nil {
		t.Fatalf("parsing the secret: %v", err)
	}
	stored, err := sealer.Seal(plain)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if again, _ := sealer.Seal(plain); plain != "" && again == stored {
		t.Fatalf("two seals of one value are identical: the nonce is not random")
	}
	if opened, err := sealer.Open(stored); err != nil || opened != plain {
		t.Fatalf("Open(Seal(%q)) = %q, %v", plain, opened, err)
	}
	return testCase{
		Name:  "seal " + map[bool]string{true: "empty", false: "a token"}[plain == ""],
		Input: map[string]string{"kind": "seal", "spec": newestSecret, "plain": plain},
		Want:  map[string]any{"prefix": stored[:min(len(stored), len(sealPrefix))], "length": len(stored)},
	}
}

func TestSealerVector(t *testing.T) {
	cases := append(openCases(t), parseCases()...)
	for _, c := range cases[:3] {
		if c.Want.(map[string]any)["error"] != nil {
			t.Fatalf("%s: the fixed-nonce construction no longer matches pg.TokenSealer", c.Name)
		}
	}
	cases = append(cases, sealCase(t, "refresh-token-1"), sealCase(t, ""))
	pin(t, "sealer", map[string]any{
		"prefix": sealPrefix, "kdf": "HKDF-SHA256", "salt": "", "info": sealInfo, "key_bytes": 32,
		"cipher": "AES-256-GCM", "nonce_bytes": 12, "aad": sealAAD, "encoding": "base64url without padding of nonce||ciphertext||tag",
	}, cases)
}
