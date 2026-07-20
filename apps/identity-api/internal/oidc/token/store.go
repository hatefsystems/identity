// Storage interfaces and in-memory implementations for authorization codes
// and refresh tokens. The interfaces isolate the protocol logic from the
// backing store so the Redis-backed implementations (docs/data-architecture.md
// §3) can be slotted in without touching grant handling. Secrets are never
// stored raw: both codes and refresh tokens are indexed by their SHA-256
// digest, so a store dump cannot be replayed against the endpoint.

package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// secretByteLen is the entropy of generated codes and refresh tokens
// (256 bits from crypto/rand).
const secretByteLen = 32

// Refresh token lifecycle states for Refresh Token Rotation (RTR).
const (
	// StatusActive marks the single currently-valid token of a family.
	StatusActive = "active"
	// StatusRotated marks a token that was exchanged for a successor. Its
	// reappearance at the endpoint is proof of theft/replay (breach).
	StatusRotated = "rotated"
	// StatusRevoked marks a token invalidated by breach detection, logout,
	// or administrative revocation.
	StatusRevoked = "revoked"
)

// Store sentinel errors.
var (
	// ErrCodeNotFound indicates the authorization code is unknown or expired.
	ErrCodeNotFound = errors.New("token: authorization code not found")
	// ErrRefreshTokenNotFound indicates the refresh token is unknown or expired.
	ErrRefreshTokenNotFound = errors.New("token: refresh token not found")
)

// AuthorizationCodeData is the server-side state bound to an issued
// authorization code, captured at the consent stage and consumed exactly once
// at the token endpoint.
type AuthorizationCodeData struct {
	ClientID string
	// RedirectURI is the canonical redirect URI the code was issued for; the
	// token request must present the identical value (RFC 6749 §4.1.3).
	RedirectURI string
	UserID      string
	Scope       string
	// Nonce is the OIDC nonce to echo into the ID token.
	Nonce string
	// CodeChallenge is the S256 PKCE challenge the exchange must satisfy.
	CodeChallenge string
	ExpiresAt     time.Time
}

// AuthorizationCodeStore persists issued authorization codes. Save stores
// data under the SHA-256 hash of the code; Consume atomically retrieves and
// deletes it, guaranteeing single use even under concurrent replay attempts.
type AuthorizationCodeStore interface {
	Save(codeHash string, data AuthorizationCodeData) error
	// Consume returns the data for codeHash and removes it in the same
	// operation. A second Consume with the same hash returns ErrCodeNotFound.
	Consume(codeHash string) (AuthorizationCodeData, error)
}

// RefreshTokenData is the server-side record of a refresh token under
// Refresh Token Rotation.
type RefreshTokenData struct {
	// FamilyID groups all rotations of one grant/session. Breach detection
	// revokes entire families.
	FamilyID  string
	UserID    string
	ClientID  string
	Scope     string
	Status    string
	ExpiresAt time.Time
}

// RefreshTokenStore persists refresh tokens keyed by SHA-256 hash.
type RefreshTokenStore interface {
	Save(tokenHash string, data RefreshTokenData) error
	Get(tokenHash string) (RefreshTokenData, error)
	// MarkRotated transitions an active token to rotated after a successful
	// exchange, keeping the record so a later replay is detectable.
	MarkRotated(tokenHash string) error
	// RevokeFamily marks every token in the family as revoked (e.g. replay of
	// a rotated token from a stolen session).
	RevokeFamily(familyID string) error
	// RevokeAllForUser marks every token of every family belonging to the
	// user as revoked — the RTR breach response: one detected replay kills
	// all active sessions for that user (docs/architecture.md "Refresh Token
	// Rotation").
	RevokeAllForUser(userID string) error
}

// NewSecret generates a 256-bit random secret (authorization code or refresh
// token) encoded as base64url, plus its SHA-256 hash used as the storage key.
func NewSecret() (secret string, hash string, err error) {
	raw := make([]byte, secretByteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("token: generate secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	return secret, HashSecret(secret), nil
}

// HashSecret returns the hex-free base64url SHA-256 digest of a secret,
// used as the storage key so raw secrets never rest in the store.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// In-memory implementations
// ---------------------------------------------------------------------------

// MemoryCodeStore is a thread-safe in-memory AuthorizationCodeStore with
// expiry enforcement. Suitable for the MVP single-node deployment and tests;
// the Redis implementation replaces it when Redis wiring lands.
type MemoryCodeStore struct {
	mu    sync.Mutex
	codes map[string]AuthorizationCodeData
	// now is injectable for expiry tests.
	now func() time.Time
}

// NewMemoryCodeStore constructs an empty MemoryCodeStore.
func NewMemoryCodeStore() *MemoryCodeStore {
	return &MemoryCodeStore{codes: make(map[string]AuthorizationCodeData), now: time.Now}
}

// Save implements AuthorizationCodeStore.
func (s *MemoryCodeStore) Save(codeHash string, data AuthorizationCodeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[codeHash] = data
	return nil
}

// Consume implements AuthorizationCodeStore. Retrieval and deletion happen
// under one lock acquisition, so exactly one caller can ever win a code.
func (s *MemoryCodeStore) Consume(codeHash string) (AuthorizationCodeData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.codes[codeHash]
	if !ok {
		return AuthorizationCodeData{}, ErrCodeNotFound
	}
	delete(s.codes, codeHash)
	if s.now().After(data.ExpiresAt) {
		return AuthorizationCodeData{}, ErrCodeNotFound
	}
	return data, nil
}

// MemoryRefreshTokenStore is a thread-safe in-memory RefreshTokenStore with
// secondary indexes by family and user for bulk revocation.
type MemoryRefreshTokenStore struct {
	mu     sync.Mutex
	tokens map[string]RefreshTokenData
	// byFamily and byUser index token hashes for O(family)/O(user) revocation.
	byFamily map[string][]string
	byUser   map[string][]string
	now      func() time.Time
}

// NewMemoryRefreshTokenStore constructs an empty MemoryRefreshTokenStore.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{
		tokens:   make(map[string]RefreshTokenData),
		byFamily: make(map[string][]string),
		byUser:   make(map[string][]string),
		now:      time.Now,
	}
}

// Save implements RefreshTokenStore.
func (s *MemoryRefreshTokenStore) Save(tokenHash string, data RefreshTokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenHash] = data
	s.byFamily[data.FamilyID] = append(s.byFamily[data.FamilyID], tokenHash)
	s.byUser[data.UserID] = append(s.byUser[data.UserID], tokenHash)
	return nil
}

// Get implements RefreshTokenStore. Expired tokens are reported as not found;
// the record is retained until natural cleanup so replay of an expired token
// never looks like an unknown token to breach analytics.
func (s *MemoryRefreshTokenStore) Get(tokenHash string) (RefreshTokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.tokens[tokenHash]
	if !ok {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	if s.now().After(data.ExpiresAt) {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	return data, nil
}

// MarkRotated implements RefreshTokenStore.
func (s *MemoryRefreshTokenStore) MarkRotated(tokenHash string) error {
	return s.setStatus(tokenHash, StatusRotated)
}

// setStatus transitions a single token's status under the lock.
func (s *MemoryRefreshTokenStore) setStatus(tokenHash, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.tokens[tokenHash]
	if !ok {
		return ErrRefreshTokenNotFound
	}
	data.Status = status
	s.tokens[tokenHash] = data
	return nil
}

// RevokeFamily implements RefreshTokenStore.
func (s *MemoryRefreshTokenStore) RevokeFamily(familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, hash := range s.byFamily[familyID] {
		if data, ok := s.tokens[hash]; ok {
			data.Status = StatusRevoked
			s.tokens[hash] = data
		}
	}
	return nil
}

// RevokeAllForUser implements RefreshTokenStore.
func (s *MemoryRefreshTokenStore) RevokeAllForUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, hash := range s.byUser[userID] {
		if data, ok := s.tokens[hash]; ok {
			data.Status = StatusRevoked
			s.tokens[hash] = data
		}
	}
	return nil
}
