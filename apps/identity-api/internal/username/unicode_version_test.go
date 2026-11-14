package username

import (
	"testing"

	"golang.org/x/text/unicode/norm"
)

// The registration-browser fixture fingerprints the same canonical artifact
// as the compiled API. x/text v0.40.0 switches tables at Go 1.27, so a Go
// toolchain bump requires an explicit policy/fixture review, never a silent
// namespace or active-authority change.
func TestPinnedUsernameUnicodeVersion(t *testing.T) {
	if got, want := norm.Version, "15.0.0"; got != want {
		t.Fatalf("username Unicode table version changed: got %s, want %s; review the immutable namespace and registration fixture before upgrading", got, want)
	}
}
