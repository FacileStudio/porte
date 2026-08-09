package avatarfs

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A one-pixel PNG. The store never parses it, but a test that round-trips real
// bytes catches a truncated write that a []byte("png") would not.
var onePixelPNG = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89,
	0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
	0x0d, 0x0a, 0x2d, 0xb4,
	0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

func newStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "avatars"), "/avatars")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

func TestNewCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "avatars")
	if _, err := New(dir, "/avatars"); err != nil {
		t.Fatalf("New: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("the path exists but is not a directory")
	}
}

func TestPrefixSpellingsAreEquivalent(t *testing.T) {
	for _, spelling := range []string{"/avatars", "avatars", "/avatars/", "avatars/"} {
		store, err := New(t.TempDir(), spelling)
		if err != nil {
			t.Fatalf("New(%q): %v", spelling, err)
		}
		if store.URLPrefix() != "/avatars" {
			t.Fatalf("New(%q).URLPrefix() = %q, want /avatars", spelling, store.URLPrefix())
		}
	}
}

func TestEmptyPrefixIsRejected(t *testing.T) {
	for _, spelling := range []string{"", " ", "/", "//"} {
		if _, err := New(t.TempDir(), spelling); err == nil {
			t.Fatalf("New accepted the prefix %q", spelling)
		}
	}
}

// The round trip is the whole package: bytes in through Put, the same bytes
// back out of Handler at the URL Put returned.
func TestPutThenServeReturnsTheSameBytes(t *testing.T) {
	store := newStore(t)

	avatarURL, err := store.Put(context.Background(), "deadbeef", onePixelPNG, "image/png")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if avatarURL != "/avatars/deadbeef.png" {
		t.Fatalf("Put returned %q, want /avatars/deadbeef.png", avatarURL)
	}

	recorder := httptest.NewRecorder()
	store.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, avatarURL, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !bytes.Equal(recorder.Body.Bytes(), onePixelPNG) {
		t.Fatalf("served %d bytes, want the %d that were stored", recorder.Body.Len(), len(onePixelPNG))
	}
	if cache := recorder.Header().Get("Cache-Control"); !strings.Contains(cache, "max-age=") {
		t.Fatalf("Cache-Control = %q, want a max-age", cache)
	}
}

func TestPutPicksTheExtensionFromTheContentType(t *testing.T) {
	store := newStore(t)
	for contentType, want := range map[string]string{
		"image/png":              "/avatars/k.png",
		"image/jpeg":             "/avatars/k.jpg",
		"image/gif":              "/avatars/k.gif",
		"image/webp":             "/avatars/k.webp",
		"image/PNG; charset=x  ": "/avatars/k.png",
	} {
		avatarURL, err := store.Put(context.Background(), "k", onePixelPNG, contentType)
		if err != nil {
			t.Fatalf("Put(%q): %v", contentType, err)
		}
		if avatarURL != want {
			t.Fatalf("Put(%q) = %q, want %q", contentType, avatarURL, want)
		}
	}
}

func TestUnknownContentTypeIsAnErrorNotADefault(t *testing.T) {
	store := newStore(t)
	for _, contentType := range []string{"", "text/html", "image/svg+xml", "application/octet-stream"} {
		if _, err := store.Put(context.Background(), "k", onePixelPNG, contentType); err == nil {
			t.Fatalf("Put accepted the content type %q", contentType)
		}
	}
	if entries, _ := os.ReadDir(store.dir); len(entries) != 0 {
		t.Fatalf("a rejected Put left %d files behind", len(entries))
	}
}

// A stable key must overwrite. The apps this replaces accumulate one file per
// login, which is how an avatar directory becomes the biggest thing in the
// backup.
func TestReputWithTheSameKeyLeavesOneFile(t *testing.T) {
	store := newStore(t)
	replacement := append(bytes.Clone(onePixelPNG), 0x00)

	first, err := store.Put(context.Background(), "stable", onePixelPNG, "image/png")
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}
	second, err := store.Put(context.Background(), "stable", replacement, "image/png")
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if first != second {
		t.Fatalf("the URL changed on re-Put: %q then %q", first, second)
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("the directory holds %v, want exactly one file", names)
	}

	stored, err := os.ReadFile(filepath.Join(store.dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(stored, replacement) {
		t.Fatal("the second Put did not replace the first")
	}
	if mode := fileMode(t, filepath.Join(store.dir, entries[0].Name())); mode != 0o644 {
		t.Fatalf("mode = %o, want 644", mode)
	}
}

// The key comes from a caller, and a caller is eventually going to hand this
// an email address or a filename rather than a hash.
func TestTraversalAndOtherBadKeysAreRejected(t *testing.T) {
	store := newStore(t)
	for _, key := range []string{
		"",
		"../../etc/passwd",
		"/etc/passwd",
		"..",
		"a/b",
		"a\\b",
		"a.b",
		"a b",
		"a\x00b",
		strings.Repeat("k", maxKeyLength+1),
	} {
		if _, err := store.Put(context.Background(), key, onePixelPNG, "image/png"); err == nil {
			t.Fatalf("Put accepted the key %q", key)
		}
	}
	if entries, _ := os.ReadDir(store.dir); len(entries) != 0 {
		t.Fatalf("a rejected key wrote %d files", len(entries))
	}
	if _, err := os.Stat("/etc/passwd.png"); err == nil {
		t.Fatal("an absolute key wrote outside the store")
	}
}

func TestRemoveDeletesThenIsANoOp(t *testing.T) {
	store := newStore(t)
	avatarURL, err := store.Put(context.Background(), "gone", onePixelPNG, "image/png")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Remove(context.Background(), avatarURL); err != nil {
		t.Fatalf("first Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.dir, "gone.png")); err == nil {
		t.Fatal("the file survived Remove")
	}
	if err := store.Remove(context.Background(), avatarURL); err != nil {
		t.Fatalf("second Remove: %v, want a no-op", err)
	}

	recorder := httptest.NewRecorder()
	store.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, avatarURL, nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status after Remove = %d, want 404", recorder.Code)
	}
}

// A URL from another store is another store's business, and a URL that walks
// out of the directory is nobody's.
func TestRemoveRefusesForeignAndEscapingURLs(t *testing.T) {
	store := newStore(t)
	if _, err := store.Put(context.Background(), "keep", onePixelPNG, "image/png"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	victim := filepath.Join(store.dir, "..", "victim.png")
	if err := os.WriteFile(victim, onePixelPNG, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, avatarURL := range []string{
		"",
		"/uploads/keep.png",
		"https://cdn.example.com/uploads/keep.png",
		"/avatars/../victim.png",
		"/avatars/../../etc/passwd",
		"/avatars/keep",
		"/avatars/keep.svg",
		"/avatars/",
	} {
		if err := store.Remove(context.Background(), avatarURL); err == nil {
			t.Fatalf("Remove accepted %q", avatarURL)
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("a file outside the directory was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.dir, "keep.png")); err != nil {
		t.Fatalf("the stored avatar was removed: %v", err)
	}
}

// The absolute form is what an app fronted by a CDN may have recorded.
func TestRemoveAcceptsAnAbsoluteURLCarryingThePrefix(t *testing.T) {
	store := newStore(t)
	if _, err := store.Put(context.Background(), "cdn", onePixelPNG, "image/png"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Remove(context.Background(), "https://cdn.example.com/avatars/cdn.png"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.dir, "cdn.png")); err == nil {
		t.Fatal("the file survived Remove")
	}
}

func TestHandlerServesNoListingAndNoStrayFiles(t *testing.T) {
	store := newStore(t)
	if _, err := store.Put(context.Background(), "visible", onePixelPNG, "image/png"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.dir, ".visible.png.tmp"), []byte("half"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	for _, target := range []string{
		"/avatars/",
		"/avatars",
		"/avatars/.visible.png.tmp",
		"/avatars/../avatarfs_test.go",
		"/avatars/visible",
		"/elsewhere/visible.png",
	} {
		recorder := httptest.NewRecorder()
		store.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", target, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "visible.png") {
			t.Fatalf("GET %s leaked a directory listing", target)
		}
	}
}

func TestHandlerRefusesWrites(t *testing.T) {
	store := newStore(t)
	if _, err := store.Put(context.Background(), "readonly", onePixelPNG, "image/png"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	recorder := httptest.NewRecorder()
	store.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/avatars/readonly.png", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE = %d, want 405", recorder.Code)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	return info.Mode().Perm()
}
