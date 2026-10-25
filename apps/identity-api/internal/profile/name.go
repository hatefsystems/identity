// Package profile implements the minimal shared account profile.
package profile

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxNameLength counts Unicode code points, not bytes or grapheme clusters.
const MaxNameLength = 80

// ErrInvalidName never includes the rejected Class A value.
var ErrInvalidName = errors.New("profile: invalid name")

// NormalizeName is shared by display names and credential labels. Controls and
// line separators are rejected before trimming, including at the edges.
func NormalizeName(name string) (string, error) {
	if !utf8.ValidString(name) || strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	}) {
		return "", ErrInvalidName
	}
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > MaxNameLength {
		return "", ErrInvalidName
	}
	return name, nil
}
