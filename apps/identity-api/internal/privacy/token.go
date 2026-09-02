package privacy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// reclaimTokenByteLen is the entropy of a reclaim token: 256 bits from
// crypto/rand, matching session tokens, authorization codes, and refresh tokens.
//
// The token is a bearer credential for an anonymous endpoint that can undo an
// account deletion, so it must be unguessable on its own — there is no session,
// no account name, and no second lookup key to narrow the search space. It is
// paired with a factor check (passkey UV or TOTP), so the token alone is not
// sufficient to reclaim, but it is sufficient to enumerate outstanding requests
// if it were weak.
const reclaimTokenByteLen = 32

// NewReclaimToken generates a fresh reclaim token and the hash stored alongside
// the deletion request.
//
// The plaintext is returned to the caller for delivery in the notification email
// and is never persisted; only hash reaches the database, so a database dump
// cannot be replayed against the reclaim endpoints. Mirrors session.NewToken /
// session.HashToken.
//
// The hash is hex-encoded SHA-256, which is always exactly 64 characters and so
// fits deletion_requests.token_hash VARCHAR(64) — the same convention as
// recovery_codes.code_hash. The token itself is base64url so it survives being
// embedded in an email link or pasted into a form without escaping.
func NewReclaimToken() (token string, hash string, err error) {
	raw := make([]byte, reclaimTokenByteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("privacy: generate reclaim token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashReclaimToken(token), nil
}

// HashReclaimToken returns the hex-encoded SHA-256 digest of a reclaim token,
// used as the database lookup key.
//
// A plain fast hash is correct here for the same reason it is correct for recovery
// codes (see internal/recovery): the input already carries 256 bits of entropy, so
// there is nothing for a memory-hard KDF to protect, while using one would hand an
// attacker a CPU-exhaustion vector on an anonymous endpoint and would break the
// O(1) indexed lookup that idx_deletion_requests_token provides.
func HashReclaimToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
