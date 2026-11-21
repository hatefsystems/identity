// Package login coordinates first-factor proof and non-session MFA authority.
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// Login failures contain no submitted secrets or account/destination diagnostics.
var (
	ErrInvalidCredentials = errors.New("login: invalid credentials")
	ErrChallengeExpired   = errors.New("login: challenge expired or exhausted")
	ErrUnavailable        = errors.New("login: unavailable")
	ErrOutcomeUnknown     = errors.New("login: outcome unknown; do not repeat mutation")
	ErrRateLimited        = errors.New("login: rate limited")
)

// UsernameLookup resolves only the admitted username namespace.
type UsernameLookup interface {
	Lookup(context.Context, string) (uuid.UUID, error)
	NormalizeLookup(string) (username.Value, error)
}

// Users supplies authoritative account snapshots, never an email lookup.
type Users interface {
	GetUserByID(context.Context, uuid.UUID) (db.User, error)
}

// Contacts authenticates proof for the account's exact current destination.
type Contacts interface {
	Contact(context.Context, uuid.UUID, string) (*contactproof.Evidence, error)
}

// Result never contains both session issuance parameters and preauthentication.
type Result struct {
	Issue             *session.IssueParams
	Preauthentication string
	ExpiresAt         time.Time
}

// Deps reuses the existing account, contact, factor and session infrastructure.
type Deps struct {
	Usernames UsernameLookup
	Users     Users
	Contacts  Contacts
	Codes     *contactcode.Service
	Pending   PendingStore
	TOTP      stepup.TOTPVerifier
	Replay    stepup.ReplayGuard
	Accounts  session.AccountState
	Limiter   ratelimit.Limiter
}

// Service coordinates proof without writing a normal session cookie itself.
type Service struct {
	deps Deps
	now  func() time.Time
}

// New requires shared MFA completion authority even when new first factors are off.
func New(deps Deps) (*Service, error) {
	if deps.Users == nil || deps.Pending == nil || deps.TOTP == nil || deps.Replay == nil || deps.Accounts == nil || deps.Limiter == nil {
		return nil, ErrUnavailable
	}
	return &Service{deps: deps, now: time.Now}, nil
}

func (s *Service) limit(ctx context.Context, name, ip string) error {
	if s.deps.Usernames == nil {
		return ErrUnavailable
	}
	if canonical, err := s.deps.Usernames.NormalizeLookup(name); err == nil {
		name = canonical.SecurityName()
	}
	key := sha256.Sum256([]byte(name))
	for _, budget := range []struct {
		key    string
		max    int
		window time.Duration
	}{
		{"rate:login:source:" + ratelimit.Subnet(ip), 60, time.Minute},
		{"rate:login:identifier:" + hex.EncodeToString(key[:]), 10, time.Minute},
	} {
		ok, err := s.deps.Limiter.Allow(ctx, budget.key, budget.max, budget.window)
		if err != nil {
			return ErrOutcomeUnknown
		}
		if !ok {
			return ErrRateLimited
		}
	}
	return nil
}

// Password verifies exact input bytes. Creation policy never runs at this boundary.
func (s *Service) Password(ctx context.Context, name, secret, jkt, ip string) (Result, error) {
	if err := s.limit(ctx, name, ip); err != nil {
		return Result{}, err
	}
	var user db.User
	var lookupErr error
	if s.deps.Usernames == nil {
		return Result{}, ErrUnavailable
	}
	id, err := s.deps.Usernames.Lookup(ctx, name)
	if err == nil {
		user, lookupErr = s.deps.Users.GetUserByID(ctx, id)
	} else {
		lookupErr = err
	}
	matched := false
	if lookupErr == nil && user.PasswordHash != nil {
		matched, err = password.VerifyContext(ctx, secret, *user.PasswordHash)
	} else {
		err = password.DummyVerifyContext(ctx, secret)
	}
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if lookupErr != nil && !errors.Is(lookupErr, username.ErrNotFound) && !errors.Is(lookupErr, pgx.ErrNoRows) && !errors.Is(lookupErr, username.ErrInvalidUsername) {
		return Result{}, ErrUnavailable
	}
	if !matched || user.ID == uuid.Nil || user.Status != "active" || user.DeletedAt.Valid {
		return Result{}, ErrInvalidCredentials
	}
	return s.Prepare(ctx, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true, DPoPJKT: jkt,
		Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: s.now().UTC()}})
}

func opaque() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// RequestCode has the same response for absent/ineligible destinations and delivery
// uncertainty. A decoy is not recorded and can never yield authentication authority.
func (s *Service) RequestCode(ctx context.Context, name, channel, jkt, ip string) (string, time.Time, error) {
	if s.deps.Codes == nil || s.deps.Usernames == nil || s.deps.Contacts == nil {
		return "", time.Time{}, ErrUnavailable
	}
	if channel != contactcode.ChannelEmail && channel != contactcode.ChannelSMS {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err := s.limit(ctx, name, ip); err != nil {
		return "", time.Time{}, err
	}
	handle, err := opaque()
	ttl := s.deps.Codes.ChallengeTTL(channel)
	if ttl == 0 {
		ttl = 3 * time.Minute
	}
	deadline := s.now().UTC().Add(ttl).Truncate(time.Millisecond)
	if err != nil {
		return "", time.Time{}, err
	}
	id, err := s.deps.Usernames.Lookup(ctx, name)
	if err != nil {
		return handle, deadline, nil
	}
	user, err := s.deps.Users.GetUserByID(ctx, id)
	if err != nil || user.Status != "active" || user.DeletedAt.Valid {
		return handle, deadline, nil
	}
	proofChannel := contactproof.Email
	if channel == contactcode.ChannelSMS {
		proofChannel = contactproof.Phone
	}
	proof, err := s.deps.Contacts.Contact(ctx, id, proofChannel)
	if err != nil || proof == nil {
		return handle, deadline, nil
	}
	issuedHandle, _, err := s.deps.Codes.Request(ctx, id, user.AuthVersion, jkt, channel, proof.Destination, ip)
	if err != nil {
		return handle, deadline, nil
	}
	// A common, conservative deadline prevents stricter channel policy or lookup
	// latency from exposing account existence. Storage keeps its own original expiry.
	return issuedHandle, deadline, nil
}

// VerifyCode consumes a purpose-bound proof and rechecks its current account/contact.
func (s *Service) VerifyCode(ctx context.Context, handle, jkt, code string) (Result, error) {
	if s.deps.Codes == nil || s.deps.Contacts == nil {
		return Result{}, ErrUnavailable
	}
	verified, err := s.deps.Codes.Verify(ctx, handle, jkt, code)
	if err != nil {
		if errors.Is(err, contactcode.ErrOutcomeUnknown) {
			return Result{}, ErrOutcomeUnknown
		}
		if errors.Is(err, contactcode.ErrInvalidCode) {
			return Result{}, ErrInvalidCredentials
		}
		if errors.Is(err, contactcode.ErrUnavailable) {
			return Result{}, ErrUnavailable
		}
		return Result{}, ErrChallengeExpired
	}
	channel := contactproof.Email
	if verified.Channel == contactcode.ChannelSMS {
		channel = contactproof.Phone
	}
	proof, err := s.deps.Contacts.Contact(ctx, verified.AccountID, channel)
	if err != nil || proof == nil || proof.Destination != verified.Destination {
		return Result{}, ErrInvalidCredentials
	}
	return s.prepare(ctx, session.IssueParams{UserID: verified.AccountID.String(), AuthVersion: verified.AuthVersion, AuthVersionSet: true, DPoPJKT: jkt,
		Evidence: session.Evidence{PrimaryMethod: session.MethodContactCode, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: s.now().UTC()}},
		&ContactBinding{Channel: channel, Destination: verified.Destination})
}

// Prepare rechecks captured authority. It never stamps a previously earned proof
// with a newer version, nor turns enrollment into authentication evidence.
func (s *Service) Prepare(ctx context.Context, p session.IssueParams) (Result, error) {
	return s.prepare(ctx, p, nil)
}

func (s *Service) contactCheck(id uuid.UUID, binding *ContactBinding) func(context.Context) error {
	return func(ctx context.Context) error {
		if s.deps.Contacts == nil || binding == nil || binding.Destination == "" || binding.Channel != contactproof.Email && binding.Channel != contactproof.Phone {
			return session.ErrAccountIneligible
		}
		proof, err := s.deps.Contacts.Contact(ctx, id, binding.Channel)
		if err != nil {
			return session.ErrStoreUnavailable
		}
		if proof == nil || proof.Destination != binding.Destination {
			return session.ErrAccountIneligible
		}
		return nil
	}
}

func (s *Service) prepare(ctx context.Context, p session.IssueParams, binding *ContactBinding) (Result, error) {
	id, err := uuid.Parse(p.UserID)
	if err != nil || p.DPoPJKT == "" || !p.AuthVersionSet || p.Evidence.AuthenticatedAt.IsZero() {
		return Result{}, ErrInvalidCredentials
	}
	if p.Evidence.PrimaryMethod == session.MethodContactCode {
		if binding == nil {
			return Result{}, ErrInvalidCredentials
		}
		p.CheckPrimaryFactor = s.contactCheck(id, binding)
	}
	user, err := s.deps.Users.GetUserByID(ctx, id)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if user.Status != "active" || user.DeletedAt.Valid || user.AuthVersion != p.AuthVersion {
		return Result{}, ErrInvalidCredentials
	}
	if !user.IsMfaEnabled || p.Evidence.TOTPSet && p.Evidence.TOTP {
		return Result{Issue: &p}, nil
	}
	handle, err := opaque()
	if err != nil {
		return Result{}, err
	}
	deadline := s.now().UTC().Add(5 * time.Minute)
	err = s.deps.Accounts.WithActive(ctx, p.UserID, p.AuthVersion, func() error {
		return s.deps.Pending.Create(ctx, handle, Pending{Issue: p, ExpiresAt: deadline, Contact: binding})
	})
	if err != nil {
		return Result{}, ErrOutcomeUnknown
	}
	return Result{Preauthentication: handle, ExpiresAt: deadline}, nil
}

// CompleteMFA reserves one attempt and shares TOTP replay protection with step-up.
func (s *Service) CompleteMFA(ctx context.Context, handle, jkt, code string) (Result, error) {
	claim, err := opaque()
	if err != nil {
		return Result{}, err
	}
	pending, err := s.deps.Pending.Claim(ctx, handle, jkt, claim)
	if err != nil {
		return Result{}, err
	}
	id, err := uuid.Parse(pending.Issue.UserID)
	if err != nil {
		return Result{}, ErrChallengeExpired
	}
	if err := s.deps.Accounts.Validate(ctx, pending.Issue.UserID, pending.Issue.AuthVersion); err != nil {
		return Result{}, ErrInvalidCredentials
	}
	if pending.Issue.Evidence.PrimaryMethod == session.MethodContactCode {
		pending.Issue.CheckPrimaryFactor = s.contactCheck(id, pending.Contact)
		if err := pending.Issue.CheckPrimaryFactor(ctx); err != nil {
			if errors.Is(err, session.ErrAccountIneligible) {
				return Result{}, ErrInvalidCredentials
			}
			return Result{}, ErrOutcomeUnknown
		}
	}
	if err := stepup.VerifyLoginTOTP(ctx, s.deps.TOTP, s.deps.Replay, id, code, s.now()); err != nil {
		if errors.Is(err, stepup.ErrInvalidCredentials) || errors.Is(err, stepup.ErrCodeReplayed) || errors.Is(err, stepup.ErrMethodUnavailable) {
			if releaseErr := s.deps.Pending.Release(ctx, handle, claim); releaseErr != nil {
				return Result{}, releaseErr
			}
			return Result{}, ErrInvalidCredentials
		}
		// An unknown replay/verification result leaves this challenge claimed.
		return Result{}, ErrOutcomeUnknown
	}
	if err := s.deps.Pending.Consume(ctx, handle, claim); err != nil {
		return Result{}, err
	}
	pending.Issue.Evidence.TOTP, pending.Issue.Evidence.TOTPSet = true, true
	if err := session.ValidateAuthority(ctx, s.deps.Accounts, pending.Issue.UserID, pending.Issue.AuthVersion, session.KindAuthenticated, pending.Issue.Evidence); err != nil {
		return Result{}, ErrInvalidCredentials
	}
	return Result{Issue: &pending.Issue}, nil
}

// DBContacts reads authenticated contact evidence through the existing envelope.
type DBContacts struct {
	Queries *db.Queries
	Cipher  contactproof.Cipher
}

// Contact returns proof only when it matches the current destination.
func (c DBContacts) Contact(ctx context.Context, id uuid.UUID, channel string) (*contactproof.Evidence, error) {
	return contactproof.Read(ctx, c.Queries, c.Cipher, id, channel)
}
