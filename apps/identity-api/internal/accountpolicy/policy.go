// Package accountpolicy evaluates resulting account protection in caller-owned transactions.
package accountpolicy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

var (
	// ErrLastCredential refuses a resulting account without a usable primary credential.
	ErrLastCredential = errors.New("accountpolicy: last primary credential")
	// ErrLastFactor refuses loss of the required privileged-account protection.
	ErrLastFactor = errors.New("accountpolicy: last privileged factor")
	// ErrLastVerifiedContact refuses removal of the only evidenced current contact.
	ErrLastVerifiedContact = errors.New("accountpolicy: last verified contact")
)

// Policy uses the same admitted username authority as the password login route.
type Policy struct {
	PasswordLoginEnabled bool
	Usernames            *username.Store
}

// Guard is acquired before the account mutex whenever password fallback is enabled.
func (p Policy) Guard(ctx context.Context, tx pgx.Tx) (username.GuardAuthority, error) {
	if !p.PasswordLoginEnabled {
		return username.GuardAuthority{}, nil
	}
	if p.Usernames == nil {
		return username.GuardAuthority{}, username.ErrUnavailable
	}
	return p.Usernames.GuardAuthority(ctx, tx)
}

// State describes only usable primary credentials and configured protection.
type State struct {
	Passkeys   int64
	Password   bool
	TOTP       bool
	Privileged bool
}

// Check evaluates the proposed state, not the account's historical protection.
func (s State) Check() error {
	if s.Passkeys == 0 && !s.Password {
		return ErrLastCredential
	}
	if s.Privileged && s.Passkeys == 0 && !s.TOTP {
		return ErrLastFactor
	}
	return nil
}

// Read must run after the caller has acquired the account advisory and row locks.
func (p Policy) Read(ctx context.Context, tx pgx.Tx, user db.User, authority username.GuardAuthority) (State, error) {
	q := db.New(tx)
	count, err := q.CountWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return State{}, err
	}
	privileged, err := q.UserHasPrivilegedRole(ctx, user.ID)
	if err != nil {
		return State{}, err
	}
	s := State{Passkeys: count, TOTP: user.IsMfaEnabled && len(user.MfaTotpSecretEncrypted) > 0, Privileged: privileged}
	if p.PasswordLoginEnabled && user.PasswordHash != nil && password.SupportedHash(*user.PasswordHash) {
		name, err := p.Usernames.GetInTx(ctx, tx, user.ID, user.AuthVersion, authority)
		if err != nil {
			return State{}, err
		}
		s.Password = name != nil
	}
	return s, nil
}

// CheckPhoneRemoval preserves unknown provenance without treating populated fields as proof.
func CheckPhoneRemoval(ctx context.Context, q *db.Queries, cipher contactproof.Cipher, user db.User) error {
	phone, err := contactproof.Read(ctx, q, cipher, user.ID, contactproof.Phone)
	if err != nil {
		return err
	}
	if phone == nil {
		return nil
	}
	email, err := contactproof.Read(ctx, q, cipher, user.ID, contactproof.Email)
	if err != nil {
		return err
	}
	if email == nil {
		return ErrLastVerifiedContact
	}
	return nil
}
