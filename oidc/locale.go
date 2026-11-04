package oidc

import "github.com/FacileStudio/porte"

// localeClaim normalises the raw `locale` claim. It arrives as any so a
// provider that sends a non-string never fails the whole login.
func localeClaim(value any) string {
	tag, _ := value.(string)
	return porte.NormalizeLocale(tag)
}
