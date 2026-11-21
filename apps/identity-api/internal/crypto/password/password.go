// Package password implements NIST-compliant Argon2id password hashing and
// verification for the Hatef Identity Platform (docs/architecture.md
// "NIST-Compliant Password Hashing", docs/threat-modeling.md §1.1).
//
// Passwords are hashed with Argon2id using strict parameters (m=64MB, t=3,
// p=4) and a cryptographically secure per-user salt. Hashes are encoded in the
// standard PHC string format so the parameters travel with each hash, enabling
// transparent parameter upgrades without a schema change. Verification uses a
// constant-time comparison (crypto/subtle) to eliminate timing side-channels.
//
// This package operates on strings; the NULL password_hash case for
// passwordless WebAuthn-only accounts (users.password_hash NULL in the schema)
// is handled by callers at the query layer, not here.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Strict Argon2id parameters. These are exported so callers, tests, and the
// rehash-upgrade path can reference the canonical values.
const (
	// Memory is the memory cost in KiB (64 MB).
	Memory uint32 = 64 * 1024
	// Iterations is the time cost (number of passes).
	Iterations uint32 = 3
	// Parallelism is the number of lanes/threads.
	Parallelism uint8 = 4
	// SaltLength is the per-user salt length in bytes.
	SaltLength int = 16
	// KeyLength is the derived hash length in bytes.
	KeyLength uint32 = 32
	// MinCodePoints and MaxPasswordBytes apply only to newly chosen passwords.
	MinCodePoints    = 15
	MaxPasswordBytes = 1024
	// Stored hashes cannot request more computation than the current cost.
	MaxEncodedHashBytes = 255
	MaxSaltLength       = 64
	MaxKeyLength        = 64
	MaxComputations     = 2
)

// argon2Version is the Argon2 algorithm version emitted/accepted in the PHC
// string (0x13 == 19). It mirrors argon2.Version.
const argon2Version = argon2.Version

// Sentinel errors for creation, admission and malformed or unsupported hashes.
// A password mismatch is NOT an error; Verify returns (false, nil) for that.
var (
	// ErrInvalidHash indicates the encoded hash is not in the expected PHC
	// format or has unparseable fields.
	ErrInvalidHash = errors.New("password: invalid encoded hash format")
	// ErrIncompatibleVariant indicates the hash is not argon2id.
	ErrIncompatibleVariant = errors.New("password: encoded hash is not argon2id")
	// ErrIncompatibleVersion indicates the hash uses an unsupported Argon2
	// version.
	ErrIncompatibleVersion = errors.New("password: incompatible argon2 version")
	ErrInvalidUTF8         = errors.New("password: invalid UTF-8")
	ErrTooShort            = errors.New("password: fewer than 15 Unicode code points")
	ErrTooLong             = errors.New("password: exceeds 1024 bytes")
	ErrCompromisedPassword = errors.New("password: compromised password")
	// ErrBusy rejects excess work without creating a queue of waiting callers.
	ErrBusy = errors.New("password: computation capacity exhausted")
)

// All entry points share this processwide gate. Only admitted work starts a
// goroutine; cancellation never releases a slot owned by a running worker.
var computations = make(chan struct{}, MaxComputations)

// params holds the decoded Argon2 cost parameters and output length from a PHC
// string.
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLen      uint32
}

// Validate checks creation policy without modifying the input bytes. Unicode
// code points, including spaces and combining marks, are counted as supplied.
func Validate(password string) error {
	if len(password) > MaxPasswordBytes {
		return ErrTooLong
	}
	if !utf8.ValidString(password) {
		return ErrInvalidUTF8
	}
	if utf8.RuneCountInString(password) < MinCodePoints {
		return ErrTooShort
	}
	if compromised(password) {
		return ErrCompromisedPassword
	}
	return nil
}

// Hash validates a newly chosen password and derives its Argon2id hash using
// the strict package parameters and a fresh random salt, returning a PHC string suitable
// for storage in the users.password_hash column, e.g.:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
func Hash(password string) (string, error) {
	return HashContext(context.Background(), password)
}

// HashContext validates a newly chosen password and hashes its exact bytes.
// It returns ErrBusy immediately when both computation slots are occupied.
func HashContext(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := Validate(password); err != nil {
		return "", err
	}
	return RehashContext(ctx, password)
}

// RehashContext upgrades an already verified password using its exact bytes,
// without applying creation rules to an existing credential.
func RehashContext(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	key, err := computeKey(ctx, func() []byte {
		return argon2.IDKey([]byte(password), salt, Iterations, Memory, Parallelism, KeyLength)
	})
	if err != nil {
		return "", err
	}

	b64 := base64.RawStdEncoding
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, Memory, Iterations, Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	)
	return encoded, nil
}

// Verify reports whether password matches the PHC-encoded Argon2id hash. It
// re-derives the key using the parameters embedded in the hash and compares in
// constant time. It returns (false, nil) on a plain mismatch, and a non-nil
// error for an invalid/unsupported hash or exhausted computation capacity.
func Verify(password, encodedHash string) (bool, error) {
	return VerifyContext(context.Background(), password, encodedHash)
}

// VerifyContext checks an existing credential without creation validation.
// Cancellation stops waiting, not a computation that has already started.
func VerifyContext(ctx context.Context, password, encodedHash string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	p, salt, key, err := decode(encodedHash)
	if err != nil {
		return false, err
	}

	other, err := computeKey(ctx, func() []byte {
		return argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLen)
	})
	if err != nil {
		return false, err
	}

	// Constant-time comparison to avoid leaking match information via timing
	// (docs/architecture.md "Timing Attack Resistance").
	if subtle.ConstantTimeCompare(key, other) == 1 {
		return true, nil
	}
	return false, nil
}

// DummyVerifyContext performs a current-cost verification for an absent
// credential. Its match result is deliberately discarded. The fixed PHC avoids
// bootstrapping another expensive hash outside the shared admission gate.
func DummyVerifyContext(ctx context.Context, password string) error {
	const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := VerifyContext(ctx, password, dummyHash)
	return err
}

func computeKey(ctx context.Context, derive func() []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case computations <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	if err := ctx.Err(); err != nil {
		<-computations
		return nil, err
	}

	result := make(chan []byte, 1)
	go func() {
		// Release after derivation, before publishing a successful result.
		key := func() []byte {
			defer func() { <-computations }()
			return derive()
		}()
		result <- key
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case key := <-result:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return key, nil
	}
}

// NeedsRehash reports whether the stored hash was produced with parameters
// weaker than the current strict values, signalling that the password should
// be transparently re-hashed on the next successful login. It returns true for
// a malformed hash so callers treat it as needing replacement.
func NeedsRehash(encodedHash string) bool {
	p, salt, _, err := decode(encodedHash)
	if err != nil {
		return true
	}
	if p.memory != Memory || p.iterations != Iterations || p.parallelism != Parallelism {
		return true
	}
	if len(salt) != SaltLength || p.keyLen != KeyLength {
		return true
	}
	return false
}

// decode parses a PHC-format argon2id string into its parameters, salt, and
// derived key.
func decode(encodedHash string) (params, []byte, []byte, error) {
	if len(encodedHash) > MaxEncodedHashBytes {
		return params{}, nil, nil, ErrInvalidHash
	}
	// Expected: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	// Leading empty segment comes from the leading '$'.
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" {
		return params{}, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return params{}, nil, nil, ErrIncompatibleVariant
	}

	version, err := parseField(parts[2], "v=", 32)
	if err != nil {
		return params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2Version {
		return params{}, nil, nil, ErrIncompatibleVersion
	}

	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return params{}, nil, nil, ErrInvalidHash
	}
	memory, err := parseField(fields[0], "m=", 32)
	if err != nil || memory == 0 || memory > uint64(Memory) {
		return params{}, nil, nil, ErrInvalidHash
	}
	iterations, err := parseField(fields[1], "t=", 32)
	if err != nil || iterations == 0 || iterations > uint64(Iterations) {
		return params{}, nil, nil, ErrInvalidHash
	}
	parallelism, err := parseField(fields[2], "p=", 8)
	if err != nil || parallelism == 0 || parallelism > uint64(Parallelism) || memory < 8*parallelism {
		return params{}, nil, nil, ErrInvalidHash
	}
	p := params{
		memory:      uint32(memory),     //nolint:gosec // G115: bounded by Memory above
		iterations:  uint32(iterations), //nolint:gosec // G115: bounded by Iterations above
		parallelism: uint8(parallelism), //nolint:gosec // G115: bounded by Parallelism above
	}

	b64 := base64.RawStdEncoding.Strict()
	// Bound both fields before DecodeString allocates its destination buffers.
	if len(parts[4]) == 0 || len(parts[4]) > b64.EncodedLen(MaxSaltLength) ||
		len(parts[5]) == 0 || len(parts[5]) > b64.EncodedLen(MaxKeyLength) ||
		strings.ContainsAny(parts[4]+parts[5], "\r\n") {
		return params{}, nil, nil, ErrInvalidHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > MaxSaltLength {
		return params{}, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 || len(key) > MaxKeyLength {
		return params{}, nil, nil, ErrInvalidHash
	}
	p.keyLen = uint32(len(key)) //nolint:gosec // G115: bounded by MaxKeyLength above

	return p, salt, key, nil
}

func parseField(field, prefix string, bits int) (uint64, error) {
	value, ok := strings.CutPrefix(field, prefix)
	if !ok || value == "" {
		return 0, ErrInvalidHash
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, ErrInvalidHash
		}
	}
	return strconv.ParseUint(value, 10, bits)
}
