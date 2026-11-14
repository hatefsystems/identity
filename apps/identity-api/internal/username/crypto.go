package username

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/google/uuid"
)

const (
	lookupDomain   = "hatef.identity.username.lookup"
	verifierDomain = "hatef.identity.username.key-verifier"
)

// Authority is exact provenance, not an additional uniqueness namespace. The
// active DB authority must be checked under the operation's transaction guard.
type Authority struct {
	PolicyID    uuid.UUID         `json:"policy_id"`
	Fingerprint [sha256.Size]byte `json:"fingerprint"`
	KeyID       string            `json:"key_id"`
	KeyVerifier [sha256.Size]byte `json:"key_verifier"`
}

func exactHMAC(key []byte, domain string, message []byte) [sha256.Size]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(message)
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}
