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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"

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
)

// argon2Version is the Argon2 algorithm version emitted/accepted in the PHC
// string (0x13 == 19). It mirrors argon2.Version.
const argon2Version = argon2.Version

// Sentinel errors returned by Verify for malformed or unsupported hashes.
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
)

// params holds the decoded Argon2 cost parameters and output length from a PHC
// string.
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLen      uint32
}

// Hash derives an Argon2id hash of password using the strict package
// parameters and a fresh random salt, returning a PHC-encoded string suitable
// for storage in the users.password_hash column, e.g.:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
func Hash(password string) (string, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, Iterations, Memory, Parallelism, KeyLength)

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
// error only when encodedHash is malformed or uses an unsupported
// variant/version.
func Verify(password, encodedHash string) (bool, error) {
	p, salt, key, err := decode(encodedHash)
	if err != nil {
		return false, err
	}

	other := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLen)

	// Constant-time comparison to avoid leaking match information via timing
	// (docs/architecture.md "Timing Attack Resistance").
	if subtle.ConstantTimeCompare(key, other) == 1 {
		return true, nil
	}
	return false, nil
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
	// Expected: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	// Leading empty segment comes from the leading '$'.
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" {
		return params{}, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return params{}, nil, nil, ErrIncompatibleVariant
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2Version {
		return params{}, nil, nil, ErrIncompatibleVersion
	}

	var p params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); err != nil {
		return params{}, nil, nil, ErrInvalidHash
	}
	if p.memory == 0 || p.iterations == 0 || p.parallelism == 0 {
		return params{}, nil, nil, ErrInvalidHash
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return params{}, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 || len(key) > math.MaxUint32 {
		return params{}, nil, nil, ErrInvalidHash
	}
	// len(key) is bounded above by math.MaxUint32 by the check above, so this
	// conversion cannot overflow.
	p.keyLen = uint32(len(key)) //nolint:gosec // G115: bounds-checked above

	return p, salt, key, nil
}
