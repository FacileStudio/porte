package oidc

import (
	"strings"

	"github.com/FacileStudio/porte"
)

// localeClaim normalises the raw `locale` claim. It arrives as any so a
// provider that sends a non-string never fails the whole login. A missing or
// non-string claim is empty, so the store keeps the locale it already holds
// and a new row takes its column default.
func localeClaim(value any) string {
	tag, ok := value.(string)
	if !ok {
		return ""
	}
	return porte.NormalizeLocale(tag)
}

// normalizeEmail trims and lowercases an address claim, as porte/local does,
// so one mailbox spelled two ways cannot become two accounts.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
