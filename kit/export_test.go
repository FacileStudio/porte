package kit

// ResetLiteralWarning lets a test observe the once-per-process warning again.
func ResetLiteralWarning() {
	literalWarned.Store(false)
}
