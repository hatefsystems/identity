package smsotp

import (
	"crypto/rand"
	"math/big"
	"regexp"
	"strings"
)

// otpDigits is the number of decimal digits in a generated SMS OTP. Six digits
// (docs/api-design.md §1.5) balances usability against the 3-attempt / 3-minute
// brute-force envelope (a random guess succeeds with probability 3/10^6).
const otpDigits = 6

// e164Pattern matches an E.164 phone number: a leading '+', a non-zero first
// digit, then up to 14 further digits (15 significant digits total, per ITU-T
// E.164). Numbers are normalized before this check so incidental spaces, dashes,
// and parentheses do not cause spurious rejections.
var e164Pattern = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// separatorStripper removes the human-friendly separators commonly typed into a
// phone field (spaces, dashes, dots, and parentheses) prior to E.164 validation.
var separatorStripper = strings.NewReplacer(
	" ", "",
	"-", "",
	".", "",
	"(", "",
	")", "",
)

// NormalizePhone canonicalizes a user-entered phone number to E.164 form and
// validates it. It strips common separators, then requires the result to be a
// well-formed E.164 number ("+" followed by 2-15 digits). The normalized value
// is what gets hashed into the blind index and envelope-encrypted, so callers
// must always store the normalized form to keep the blind index stable.
func NormalizePhone(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrInvalidPhone
	}

	normalized := separatorStripper.Replace(trimmed)
	if !e164Pattern.MatchString(normalized) {
		return "", ErrInvalidPhone
	}
	return normalized, nil
}

// generateCode returns a zero-padded 6-digit OTP drawn from a cryptographically
// secure source (crypto/rand). Sampling a uniform integer in [0, 10^6) via
// rand.Int avoids the modulo bias a naive byte-to-digit mapping would introduce.
func generateCode() (string, error) {
	upperBound := big.NewInt(1_000_000) // 10^otpDigits
	n, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return "", err
	}

	// %06d zero-pads so codes like 42 render as "000042".
	return zeroPad(n.Int64()), nil
}

// zeroPad renders n as a fixed-width otpDigits decimal string.
func zeroPad(n int64) string {
	const width = otpDigits
	s := big.NewInt(n).String()
	if len(s) >= width {
		return s
	}
	return strings.Repeat("0", width-len(s)) + s
}
