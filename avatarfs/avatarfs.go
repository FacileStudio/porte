// Package avatarfs stores IdP avatars on the local filesystem and serves them
// back over HTTP.
//
// Five apps in the suite carry their own copy of this file, and the
// differences between them are accidental rather than deliberate: a different
// extension table, a different permission bit, a write that is not atomic.
// This is the one version, and it is the boring one — a directory, a URL
// prefix, and no configuration beyond those two.
//
// It implements porte.AvatarStore. An app that keeps avatars in object storage
// writes its own; an app that has a disk should not.
package avatarfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/FacileStudio/porte"
)

var _ porte.AvatarStore = (*Store)(nil)

// extensions maps the content types porte's avatar fetch already validates to
// the extension the file is written under. An unknown type is an error rather
// than a default: guessing ".png" for something that is not a PNG produces a
// file that every browser refuses and no log line explains.
var extensions = map[string]string{
	"image/png":  "png",
	"image/jpeg": "jpg",
	"image/gif":  "gif",
	"image/webp": "webp",
}

// maxKeyLength bounds the filename. The key is a hex hash today, well under
// this, but a filesystem answers a 300-byte name with ENAMETOOLONG rather than
// something a caller can act on.
const maxKeyLength = 128

// cacheControl is what Handler sends. Five minutes, not a year: the URL is
// stable per identity, so the same URL serves different bytes after a profile
// re-sync — an immutable or year-long max-age would leave the old face on
// screen until the browser cache was cleared by hand. Five minutes matches the
// suite's profile sync interval, so a stale avatar outlives the sync that
// replaced it by at most one interval, and the bytes are still served from
// cache on every page of a session.
const cacheControl = "public, max-age=300"

// Store writes avatars under a directory and serves them from a URL prefix.
type Store struct {
	dir string

	// prefix is normalised to a leading slash and no trailing one, so that
	// "/avatars", "avatars" and "/avatars/" are the same store.
	prefix string
}

// New prepares the directory, creating it when it does not exist, and returns
// a store serving it under urlPrefix.
//
// urlPrefix is the path the app mounts Handler at, not a full URL: the
// returned avatar URLs are site-relative, which is what keeps a store from
// having to know the public hostname it is behind.
func New(dir, urlPrefix string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("porte/avatarfs: the avatar directory is empty")
	}
	prefix := "/" + strings.Trim(strings.TrimSpace(urlPrefix), "/")
	if prefix == "/" {
		return nil, errors.New("porte/avatarfs: the URL prefix is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("porte/avatarfs: creating %s: %w", dir, err)
	}
	return &Store{dir: dir, prefix: prefix}, nil
}

// URLPrefix returns the normalised prefix, which is what an app should mount
// Handler at rather than repeating its own spelling of it.
func (s *Store) URLPrefix() string { return s.prefix }

// Put writes the avatar and returns the URL to record.
//
// The write is a temp file in the same directory followed by a rename, because
// the same directory is being served: a plain create-then-write is readable
// while it is still half a PNG, and the reader that catches it is a user
// looking at their own broken profile picture.
//
// The key is opaque to the store but it is not trusted by it — see the key
// rules on Remove. Writing the same key again replaces the file, which is the
// point of a stable key: a re-sync overwrites instead of accumulating one file
// per login.
func (s *Store) Put(_ context.Context, key string, data []byte, contentType string) (string, error) {
	name, err := s.filename(key, contentType)
	if err != nil {
		return "", err
	}

	// The temp name is dotted so that a crash between create and rename
	// leaves something that is visibly not an avatar rather than a file
	// the serving half would happily hand out.
	temp, err := os.CreateTemp(s.dir, "."+name+".*")
	if err != nil {
		return "", fmt.Errorf("porte/avatarfs: creating a temp file in %s: %w", s.dir, err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return "", fmt.Errorf("porte/avatarfs: writing %s: %w", tempPath, err)
	}
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return "", fmt.Errorf("porte/avatarfs: setting the mode on %s: %w", tempPath, err)
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("porte/avatarfs: closing %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, filepath.Join(s.dir, name)); err != nil {
		return "", fmt.Errorf("porte/avatarfs: publishing %s: %w", name, err)
	}
	return s.prefix + "/" + name, nil
}

// Remove deletes the file an avatar URL points at, and does nothing when it is
// already gone — a profile cleared twice is not an error.
//
// It accepts what Put returned, a site-relative URL, and also an absolute one
// whose path carries the prefix, since an app fronted by a CDN may have stored
// the absolute form. Anything else is refused: a URL that does not carry the
// prefix belongs to another store, and this one has no business deleting it.
func (s *Store) Remove(_ context.Context, avatarURL string) error {
	name, err := s.name(avatarURL)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("porte/avatarfs: removing %s: %w", name, err)
	}
	return nil
}

// Handler serves the stored avatars. It strips the prefix itself, so it can be
// mounted whole — chi's `router.Handle(store.URLPrefix()+"/*", store.Handler())`
// or a `http.ServeMux` pattern of the prefix plus a slash — without a
// StripPrefix the caller has to spell correctly for the store to be safe.
//
// It serves nothing but files whose names Put could have written: no directory
// listing, no path with a separator in it, no extension outside the table
// above. That is a stricter rule than http.FileServer's, and it is the rule
// that makes serving a directory that also holds temp files acceptable.
func (s *Store) Handler() http.Handler { return http.HandlerFunc(s.serve) }

func (s *Store) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, err := s.name(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	full := filepath.Join(s.dir, name)
	if info, err := os.Stat(full); err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", cacheControl)
	http.ServeFile(w, r, full)
}

// name maps a URL or a request path back to the file it names, refusing
// anything this store did not write.
func (s *Store) name(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("porte/avatarfs: %q is not a URL: %w", rawURL, err)
	}
	// Cleaning first is what turns "/avatars/../../etc/passwd" into a
	// path that fails the prefix test instead of one that passes it.
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	rest, found := strings.CutPrefix(cleaned, s.prefix+"/")
	if !found {
		return "", fmt.Errorf("porte/avatarfs: %q is not under %s", rawURL, s.prefix)
	}
	base, ext, found := strings.Cut(rest, ".")
	if !found {
		return "", fmt.Errorf("porte/avatarfs: %q has no extension", rawURL)
	}
	if err := validateKey(base); err != nil {
		return "", err
	}
	if !knownExtension(ext) {
		return "", fmt.Errorf("porte/avatarfs: %q is not an avatar extension", ext)
	}
	return base + "." + ext, nil
}

func (s *Store) filename(key, contentType string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	// The parameters are dropped rather than refused: porte's own fetch
	// hands over a bare type, but a caller passing the header through
	// verbatim means "image/png; charset=binary", and failing that is a
	// confusing answer to a correct PNG.
	bare, _, _ := strings.Cut(contentType, ";")
	ext, ok := extensions[strings.ToLower(strings.TrimSpace(bare))]
	if !ok {
		return "", fmt.Errorf("porte/avatarfs: unsupported avatar content type %q", contentType)
	}
	return key + "." + ext, nil
}

// validateKey refuses any key that is not a plain token.
//
// The key is Claims.AvatarKey() today, a hex hash, and every character below
// would pass. The rule is not for that caller: a store that joins a
// caller-supplied string onto a filesystem path is a directory traversal
// waiting for its second caller, and the second caller is the one who will
// pass an email address, a subject from an ID token, or a filename.
func validateKey(key string) error {
	if key == "" {
		return errors.New("porte/avatarfs: the avatar key is empty")
	}
	if len(key) > maxKeyLength {
		return fmt.Errorf("porte/avatarfs: the avatar key is longer than %d characters", maxKeyLength)
	}
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("porte/avatarfs: the avatar key %q is not a plain token", key)
		}
	}
	return nil
}

func knownExtension(ext string) bool {
	for _, known := range extensions {
		if ext == known {
			return true
		}
	}
	return false
}
