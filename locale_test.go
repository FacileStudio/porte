package porte

import "testing"

// TestNormalizeLocale pins the four languages, the prefix match and the
// fallback for everything else.
func TestNormalizeLocale(t *testing.T) {
	cases := map[string]string{
		"fr": "fr", "fr-FR": "fr", "FR_ca": "fr", " de-CH ": "de", "es-419": "es", "en-GB": "en",
		"": "en", "it": "en", "french": "en", "f": "en", "-fr": "en", "zh-Hant-TW": "en", "fr\x00": "en",
	}
	for tag, want := range cases {
		if got := NormalizeLocale(tag); got != want {
			t.Errorf("NormalizeLocale(%q) = %q, want %q", tag, got, want)
		}
	}
}
