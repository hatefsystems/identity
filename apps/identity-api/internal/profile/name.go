// Package profile implements the minimal shared account profile.
package profile

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
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

// Private-name bounds are independent of cosmetic display names and labels.
const (
	MaxPersonalNameLength = 80
	MaxPersonalNameBytes  = 1024
)

// ErrInvalidPersonalName never includes the rejected private value.
var ErrInvalidPersonalName = errors.New("profile: invalid personal name")

// NormalizePersonalName validates either required private given/family name.
// Separators are checked structurally, not as linguistic or legal-name proof.
func NormalizePersonalName(name string) (string, error) {
	if len(name) > MaxPersonalNameBytes || !utf8.ValidString(name) {
		return "", ErrInvalidPersonalName
	}
	name = strings.Trim(norm.NFC.String(name), " ")
	const letters = "\u0621\u0622\u0624\u0626\u0627\u0628\u062a\u062b\u062c\u062d\u062e\u062f\u0630\u0631\u0632\u0633\u0634\u0635\u0636\u0637\u0638\u0639\u063a\u0641\u0642\u0644\u0645\u0646\u0647\u0648\u067e\u0686\u0698\u06a9\u06af\u06cc"
	var result strings.Builder
	var previous rune
	count := 0
	for _, r := range name {
		switch r {
		case '\u064a':
			r = '\u06cc'
		case '\u0643':
			r = '\u06a9'
		}
		if r == ' ' && previous == ' ' {
			continue
		}
		if r == ' ' || r == '\u200c' {
			if !strings.ContainsRune(letters, previous) {
				return "", ErrInvalidPersonalName
			}
		} else if !strings.ContainsRune(letters, r) {
			return "", ErrInvalidPersonalName
		}
		count++
		if count > MaxPersonalNameLength {
			return "", ErrInvalidPersonalName
		}
		result.WriteRune(r)
		previous = r
	}
	if !strings.ContainsRune(letters, previous) || result.Len() > MaxPersonalNameBytes {
		return "", ErrInvalidPersonalName
	}
	return result.String(), nil
}
