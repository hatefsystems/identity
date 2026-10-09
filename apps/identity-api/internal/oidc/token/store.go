package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const secretByteLen = 32

// Credential states and principal kinds persisted with OAuth grants.
const (
	StatusActive    = "active"
	StatusRotated   = "rotated"
	StatusRevoked   = "revoked"
	PrincipalUser   = "user"
	PrincipalClient = "client"
)

var (
	// ErrCodeNotFound includes consumed and expired authorization codes.
	ErrCodeNotFound = errors.New("token: authorization code not found")
	// ErrRefreshTokenNotFound identifies absent or expired refresh authority.
	ErrRefreshTokenNotFound = errors.New("token: refresh token not found")
	// ErrGrantNotFound identifies absent or expired grant authority.
	ErrGrantNotFound = errors.New("token: grant not found")
	// ErrRefreshReuse identifies a refresh secret that was already retired.
	ErrRefreshReuse = errors.New("token: refresh token already consumed")
	// ErrStoreUnavailable distinguishes corrupt or unavailable state from denial.
	ErrStoreUnavailable = errors.New("token: credential state unavailable")
)

// AuthorizationCodeData is captured from an authenticated normal browser
// session. Session/version linkage is never supplied by an OAuth client.
type AuthorizationCodeData struct {
	AuthVersion    int64     `json:"auth_version,string"`
	AuthVersionSet bool      `json:"auth_version_set"`
	SessionID      string    `json:"session_id"`
	ClientID       string    `json:"client_id"`
	RedirectURI    string    `json:"redirect_uri"`
	UserID         string    `json:"user_id"`
	Scope          string    `json:"scope"`
	Nonce          string    `json:"nonce"`
	CodeChallenge  string    `json:"code_challenge"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// AuthorizationCodeStore stores code hashes and consumes each code at most once.
type AuthorizationCodeStore interface {
	Save(context.Context, string, AuthorizationCodeData) error
	Consume(context.Context, string) (AuthorizationCodeData, error)
}

// GrantData is the positive authority for every access token in an OAuth grant.
// Refresh rotation does not replace it or invalidate older access tokens.
type GrantData struct {
	ID             string    `json:"id"`
	PrincipalType  string    `json:"principal_type"`
	Subject        string    `json:"subject"`
	ClientID       string    `json:"client_id"`
	Scope          string    `json:"scope"`
	SessionID      string    `json:"session_id"`
	AuthVersion    int64     `json:"auth_version,string"`
	AuthVersionSet bool      `json:"auth_version_set"`
	DPoPJKT        string    `json:"dpop_jkt"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// RefreshTokenData binds one refresh secret to its immutable grant authority.
type RefreshTokenData struct {
	AuthVersion    int64     `json:"auth_version,string"`
	AuthVersionSet bool      `json:"auth_version_set"`
	FamilyID       string    `json:"family_id"`
	SessionID      string    `json:"session_id"`
	UserID         string    `json:"user_id"`
	ClientID       string    `json:"client_id"`
	Scope          string    `json:"scope"`
	DPoPJKT        string    `json:"dpop_jkt"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// GrantReader retrieves current authority without renewing its lifetime.
type GrantReader interface {
	GetGrant(context.Context, string) (GrantData, error)
}

// RefreshTokenStore atomically creates grants and rotates refresh secrets. A consumed
// refresh secret remains recorded until its grant expires, for reuse detection.
type RefreshTokenStore interface {
	GrantReader
	CreateGrant(context.Context, GrantData, string, RefreshTokenData) error
	Get(context.Context, string) (RefreshTokenData, error)
	Rotate(context.Context, string, RefreshTokenData, string, RefreshTokenData) error
	RevokeFamily(context.Context, string) error
	RevokeAllForUser(context.Context, string) error
}

// NewSecret returns a 256-bit bearer secret and the hash safe to persist.
func NewSecret() (secret string, hash string, err error) {
	raw := make([]byte, secretByteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("token: generate secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	return secret, HashSecret(secret), nil
}

// HashSecret derives the opaque lookup key for a high-entropy bearer secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validGrant(g GrantData) bool {
	if g.ID == "" || g.Subject == "" || g.ClientID == "" || g.ExpiresAt.IsZero() ||
		(g.Status != StatusActive && g.Status != StatusRevoked) {
		return false
	}
	switch g.PrincipalType {
	case PrincipalUser:
		return g.SessionID != "" && g.AuthVersionSet && g.AuthVersion >= 0
	case PrincipalClient:
		return g.Subject == g.ClientID && g.SessionID == "" && !g.AuthVersionSet && g.AuthVersion == 0
	default:
		return false
	}
}

func refreshMatchesGrant(r RefreshTokenData, g GrantData) bool {
	return g.PrincipalType == PrincipalUser && r.FamilyID == g.ID && r.UserID == g.Subject &&
		r.ClientID == g.ClientID && r.SessionID == g.SessionID && r.Scope == g.Scope &&
		r.DPoPJKT == g.DPoPJKT && r.AuthVersionSet && r.AuthVersion == g.AuthVersion &&
		!r.ExpiresAt.IsZero() && !r.ExpiresAt.After(g.ExpiresAt)
}

func validCode(c AuthorizationCodeData) bool {
	return c.UserID != "" && c.SessionID != "" && c.ClientID != "" && c.RedirectURI != "" &&
		c.CodeChallenge != "" && c.AuthVersionSet && c.AuthVersion >= 0 && !c.ExpiresAt.IsZero()
}

func storeError(err error) error {
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}

// MemoryCodeStore is single-process code authority for tests and development.
type MemoryCodeStore struct {
	mu    sync.Mutex
	codes map[string]AuthorizationCodeData
	now   func() time.Time
}

// NewMemoryCodeStore constructs an empty single-use code store.
func NewMemoryCodeStore() *MemoryCodeStore {
	return &MemoryCodeStore{codes: make(map[string]AuthorizationCodeData), now: time.Now}
}

// Save inserts captured code authority without replacing an existing code.
func (s *MemoryCodeStore) Save(ctx context.Context, hash string, data AuthorizationCodeData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if hash == "" || !validCode(data) || !data.ExpiresAt.After(s.now()) {
		return ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.codes[hash]; exists {
		return ErrStoreUnavailable
	}
	s.codes[hash] = data
	return nil
}

// Consume removes a code before returning its captured authority.
func (s *MemoryCodeStore) Consume(ctx context.Context, hash string) (AuthorizationCodeData, error) {
	if err := ctx.Err(); err != nil {
		return AuthorizationCodeData{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.codes[hash]
	delete(s.codes, hash)
	if !ok || !data.ExpiresAt.After(s.now()) {
		return AuthorizationCodeData{}, ErrCodeNotFound
	}
	if !validCode(data) {
		return AuthorizationCodeData{}, ErrStoreUnavailable
	}
	return data, nil
}

// MemoryRefreshTokenStore serializes grant mutations within one process.
type MemoryRefreshTokenStore struct {
	mu     sync.Mutex
	tokens map[string]RefreshTokenData
	grants map[string]GrantData
	now    func() time.Time
}

// NewMemoryRefreshTokenStore constructs isolated development grant authority.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{tokens: make(map[string]RefreshTokenData), grants: make(map[string]GrantData), now: time.Now}
}

// CreateGrant inserts a grant and optional first refresh secret atomically.
func (s *MemoryRefreshTokenStore) CreateGrant(ctx context.Context, grant GrantData, hash string, refresh RefreshTokenData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validGrant(grant) || grant.Status != StatusActive || !grant.ExpiresAt.After(s.now()) ||
		(grant.PrincipalType == PrincipalUser && (hash == "" || !refreshMatchesGrant(refresh, grant) || refresh.Status != StatusActive || !refresh.ExpiresAt.After(s.now()))) ||
		(grant.PrincipalType == PrincipalClient && hash != "") {
		return ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[grant.ID]; exists {
		return ErrStoreUnavailable
	}
	if hash != "" {
		if _, exists := s.tokens[hash]; exists {
			return ErrStoreUnavailable
		}
		s.tokens[hash] = refresh
	}
	s.grants[grant.ID] = grant
	return nil
}

// GetGrant returns current grant state without extending its expiry.
func (s *MemoryRefreshTokenStore) GetGrant(ctx context.Context, id string) (GrantData, error) {
	if err := ctx.Err(); err != nil {
		return GrantData{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grantLocked(id)
}

func (s *MemoryRefreshTokenStore) grantLocked(id string) (GrantData, error) {
	g, ok := s.grants[id]
	if !ok || !g.ExpiresAt.After(s.now()) {
		return GrantData{}, ErrGrantNotFound
	}
	if g.ID != id || !validGrant(g) {
		return GrantData{}, ErrStoreUnavailable
	}
	return g, nil
}

// Get retains consumed-secret evidence while its grant can remain usable.
func (s *MemoryRefreshTokenStore) Get(ctx context.Context, hash string) (RefreshTokenData, error) {
	if err := ctx.Err(); err != nil {
		return RefreshTokenData{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked(hash)
}

func (s *MemoryRefreshTokenStore) refreshLocked(hash string) (RefreshTokenData, error) {
	r, ok := s.tokens[hash]
	if !ok {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	g, err := s.grantLocked(r.FamilyID)
	if errors.Is(err, ErrGrantNotFound) {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	if err != nil {
		return RefreshTokenData{}, err
	}
	if !refreshMatchesGrant(r, g) || (r.Status != StatusActive && r.Status != StatusRotated && r.Status != StatusRevoked) {
		return RefreshTokenData{}, ErrStoreUnavailable
	}
	if g.Status == StatusRevoked {
		r.Status = StatusRevoked
	}
	if r.Status == StatusActive && !r.ExpiresAt.After(s.now()) {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	return r, nil
}

// Rotate retires the expected secret and creates its successor in one mutation.
func (s *MemoryRefreshTokenStore) Rotate(ctx context.Context, hash string, expected RefreshTokenData, nextHash string, next RefreshTokenData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.refreshLocked(hash)
	if err != nil {
		return err
	}
	if current.Status != StatusActive {
		return ErrRefreshReuse
	}
	g, err := s.grantLocked(current.FamilyID)
	if err != nil {
		return err
	}
	if current != expected || !refreshMatchesGrant(next, g) || next.Status != StatusActive ||
		nextHash == "" || !next.ExpiresAt.After(s.now()) {
		return ErrStoreUnavailable
	}
	if _, exists := s.tokens[nextHash]; exists {
		return ErrStoreUnavailable
	}
	current.Status = StatusRotated
	s.tokens[hash] = current
	s.tokens[nextHash] = next
	return nil
}

// RevokeFamily invalidates the grant and every associated access/refresh token.
func (s *MemoryRefreshTokenStore) RevokeFamily(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.grants[id]; ok {
		g.Status = StatusRevoked
		s.grants[id] = g
	}
	return nil
}

// RevokeAllForUser invalidates every existing grant owned by the user.
func (s *MemoryRefreshTokenStore) RevokeAllForUser(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.PrincipalType == PrincipalUser && g.Subject == userID {
			g.Status = StatusRevoked
			s.grants[id] = g
		}
	}
	return nil
}
