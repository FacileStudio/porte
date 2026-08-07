package oidc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// MaxAvatarBytes is the ceiling on a fetched avatar, unchanged from the apps.
const MaxAvatarBytes = 5 << 20

// avatarTimeout bounds the whole fetch. An IdP that hangs must not hang the
// login with it.
const avatarTimeout = 10 * time.Second

// FetchAvatar downloads a picture URL asserted by an identity provider and
// returns the bytes and their content type.
//
// This is the one function in porte where copy-paste drift would be a
// vulnerability rather than an inconsistency: the URL comes from an ID token,
// so it is attacker-influenced input handed to an HTTP client running inside
// the app's network. Six divergent copies exist today; this is the version
// they should all have been.
//
// The guard is applied at connect time, not before it. Every existing copy
// resolves the hostname, checks the addresses, and then calls http.Get, which
// resolves again — a DNS entry that answers publicly on the first lookup and
// privately on the second walks straight through. Checking inside the dialer
// closes that window, and covers redirects for free.
func FetchAvatar(ctx context.Context, pictureURL string) (data []byte, contentType string, err error) {
	if err := requireHTTPS(pictureURL); err != nil {
		return nil, "", err
	}

	client := &http.Client{
		Timeout: avatarTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(network, address string, _ syscall.RawConn) error {
					host, _, splitErr := net.SplitHostPort(address)
					if splitErr != nil {
						return fmt.Errorf("porte: unparseable dial address %q", address)
					}
					if ip := net.ParseIP(host); ip == nil || !isPublicIP(ip) {
						return fmt.Errorf("porte: refusing to fetch an avatar from a non-public address (%s)", host)
					}
					return nil
				},
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("porte: too many redirects fetching the avatar")
			}
			return requireHTTPS(req.URL.String())
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pictureURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("porte: invalid picture URL: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("porte: avatar fetch failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("porte: avatar fetch returned status %d", response.StatusCode)
	}
	contentType = strings.TrimSpace(strings.SplitN(response.Header.Get("Content-Type"), ";", 2)[0])
	if !isImageType(contentType) {
		return nil, "", fmt.Errorf("porte: unsupported avatar content type %q", contentType)
	}

	// One byte past the limit, so an oversized body is detected rather
	// than silently truncated into a corrupt image.
	data, err = io.ReadAll(io.LimitReader(response.Body, MaxAvatarBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("porte: reading the avatar failed: %w", err)
	}
	if len(data) > MaxAvatarBytes {
		return nil, "", fmt.Errorf("porte: avatar exceeds the %d byte limit", MaxAvatarBytes)
	}
	return data, contentType, nil
}

func requireHTTPS(rawURL string) error {
	if !strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		return fmt.Errorf("porte: avatar URLs must be https, got %q", rawURL)
	}
	return nil
}

// isPublicIP rejects everything an SSRF wants to reach: loopback, the private
// ranges, link-local — which is where a cloud metadata service lives — and the
// unspecified, multicast and IPv6 unique-local blocks.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	// IPv4-mapped and 6to4 forms of a private address are still that
	// address; net.IP.IsPrivate only understands the plain forms.
	if mapped := ip.To4(); mapped != nil && !mapped.Equal(ip) {
		return isPublicIP(mapped)
	}
	return true
}

func isImageType(contentType string) bool {
	switch contentType {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	default:
		return false
	}
}
