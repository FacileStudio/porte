package oidc

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateAddressesAreNotPublic(t *testing.T) {
	private := []string{
		"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", // the cloud metadata service, the classic SSRF target
		"0.0.0.0", "::", "fe80::1", "224.0.0.1", "::ffff:127.0.0.1",
	}
	for _, address := range private {
		if isPublicIP(net.ParseIP(address)) {
			t.Errorf("%s was treated as public", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "93.184.216.34", "2606:4700::1111"} {
		if !isPublicIP(net.ParseIP(address)) {
			t.Errorf("%s was treated as private", address)
		}
	}
}

func TestAvatarFetchRefusesPlainHTTP(t *testing.T) {
	_, _, err := FetchAvatar(context.Background(), "http://example.com/a.png")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want an https complaint", err)
	}
}

// The guard runs in the dialer, not before it, so a hostname that resolves to
// a private address is refused at connect time — which is also what closes the
// window every existing copy leaves open between its DNS check and its GET.
func TestAvatarFetchRefusesAPrivateAddressAtDialTime(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("not really a png"))
	}))
	defer server.Close()

	// httptest listens on loopback, which is exactly the case the guard
	// exists for: a valid https URL pointing inside the network.
	_, _, err := FetchAvatar(context.Background(), server.URL)
	if err == nil {
		t.Fatal("fetched an avatar from loopback")
	}
	if !strings.Contains(err.Error(), "non-public address") {
		t.Fatalf("err = %v, want the address guard to be what refused", err)
	}
}

func TestUnsupportedContentTypesAreRejected(t *testing.T) {
	if isImageType("text/html") || isImageType("application/octet-stream") || isImageType("") {
		t.Fatal("a non-image content type was accepted")
	}
	for _, contentType := range []string{"image/png", "image/jpeg", "image/gif", "image/webp"} {
		if !isImageType(contentType) {
			t.Fatalf("%s was rejected", contentType)
		}
	}
}
