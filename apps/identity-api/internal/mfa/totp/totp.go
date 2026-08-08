// Package totp implements Time-based One-Time Password (TOTP) generation and
// verification per RFC 6238 and RFC 4226 (HOTP) using the Go standard library,
// per Task 4.4.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultSecretBytes is 20 bytes (160 bits), matching RFC 4226 / RFC 6238
	// recommended minimum secret length for HMAC-SHA1. Base32 encoded without
	// padding, this yields a 32-character secret string.
	defaultSecretBytes = 20

	// periodSeconds is the standard TOTP time step duration (30 seconds).
	periodSeconds = 30

	// digits is the standard 6-digit OTP output length.
	digits = 6
)

var (
	// ErrInvalidSecret indicates the secret string is empty or invalid Base32.
	ErrInvalidSecret = errors.New("totp: invalid base32 secret")
	// ErrInvalidCode indicates the passcode is not a 6-digit numeric string.
	ErrInvalidCode = errors.New("totp: invalid code format")
)

// GenerateSecret creates a fresh CSPRNG 160-bit (20-byte) TOTP secret, returned
// as an unpadded, uppercase Base32 string (32 characters).
func GenerateSecret() (string, error) {
	b := make([]byte, defaultSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateURI builds a standard keyuri string per Google Authenticator /
// KeyUriFormat specification for QR code rendering:
//
//	otpauth://totp/{issuer}:{accountName}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
func GenerateURI(secret, accountName, issuer string) string {
	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	cleanAccount := strings.TrimSpace(accountName)
	cleanIssuer := strings.TrimSpace(issuer)

	label := cleanAccount
	if cleanIssuer != "" {
		label = cleanIssuer + ":" + cleanAccount
	}

	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + label,
	}

	q := url.Values{}
	q.Set("secret", cleanSecret)
	if cleanIssuer != "" {
		q.Set("issuer", cleanIssuer)
	}
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", periodSeconds))

	u.RawQuery = q.Encode()
	return u.String()
}

// GenerateCode calculates the 6-digit TOTP passcode for secret at time t.
func GenerateCode(secret string, t time.Time) (string, error) {
	secretBytes, err := parseSecret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix() / periodSeconds)
	return calculateHOTP(secretBytes, counter)
}

// ValidateCode checks if passcode is a valid 6-digit TOTP code for secret at
// time t within ±windowSteps time steps (e.g. windowSteps = 1 checks t-30s,
// t, t+30s). Verification uses constant-time string comparison.
func ValidateCode(secret, passcode string, t time.Time, windowSteps int) bool {
	cleanPasscode := strings.TrimSpace(passcode)
	if len(cleanPasscode) != digits {
		return false
	}
	for _, ch := range cleanPasscode {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	secretBytes, err := parseSecret(secret)
	if err != nil {
		return false
	}

	currentCounter := uint64(t.Unix() / periodSeconds)

	if windowSteps < 0 {
		windowSteps = 0
	}

	valid := false
	for i := -windowSteps; i <= windowSteps; i++ {
		var counter uint64
		if i < 0 {
			sub := uint64(-i)
			if currentCounter < sub {
				continue
			}
			counter = currentCounter - sub
		} else {
			counter = currentCounter + uint64(i)
		}

		expected, err := calculateHOTP(secretBytes, counter)
		if err != nil {
			continue
		}

		if subtle.ConstantTimeCompare([]byte(expected), []byte(cleanPasscode)) == 1 {
			valid = true
		}
	}

	return valid
}

// parseSecret normalises and Base32-decodes a secret string (supporting both
// padded and unpadded input).
func parseSecret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.TrimSpace(secret))
	if clean == "" {
		return nil, ErrInvalidSecret
	}

	// Try unpadded first
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err == nil && len(b) > 0 {
		return b, nil
	}

	// Try padded
	b, err = base32.StdEncoding.DecodeString(clean)
	if err == nil && len(b) > 0 {
		return b, nil
	}

	return nil, ErrInvalidSecret
}

// calculateHOTP calculates HMAC-SHA1 dynamic truncation per RFC 4226.
func calculateHOTP(secret []byte, counter uint64) (string, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	hash := mac.Sum(nil)

	// Dynamic truncation: offset is low 4 bits of last byte
	offset := hash[len(hash)-1] & 0x0f

	// Read 4 bytes starting at offset, masking sign bit
	binaryCode := (uint32(hash[offset]&0x7f) << 24) |
		(uint32(hash[offset+1]&0xff) << 16) |
		(uint32(hash[offset+2]&0xff) << 8) |
		(uint32(hash[offset+3] & 0xff))

	otp := binaryCode % uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, otp), nil
}
