package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

// signupCeremony is SQL-encrypted by the signup owner, never a login challenge.
type signupCeremony struct {
	Purpose string                 `json:"purpose"`
	JKT     string                 `json:"jkt"`
	Email   string                 `json:"email"`
	Session gowebauthn.SessionData `json:"session"`
	Expires time.Time              `json:"expires"`
}

// BeginSignup performs no persistence and does not relax session enrollment.
func (s *Service) BeginSignup(ctx context.Context, email string, handle []byte, jkt string, expires time.Time) (*protocol.CredentialCreation, json.RawMessage, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if !emailaddress.ValidCanonicalMailbox(email) || len(handle) != userHandleByteLen || jkt == "" || !s.now().Before(expires) || expires.After(s.now().Add(5*time.Minute)) {
		return nil, nil, ErrInvalidResponse
	}
	creation, session, err := s.wa.BeginRegistration(newUserAdapter(db.User{Email: email}, handle, nil),
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(), ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		return nil, nil, ErrVerification
	}
	creation.Response.Timeout = int(expires.Sub(s.now()).Milliseconds())
	blob, err := json.Marshal(signupCeremony{Purpose: "registration", JKT: jkt, Email: email, Session: *session, Expires: expires})
	if err != nil {
		return nil, nil, ErrVerification
	}
	return creation, blob, nil
}

// VerifySignup verifies only cryptography against a frozen SQL snapshot. The
// caller must lock/recheck revision/proofs/expiry and supply the newly born UUID.
func (s *Service) VerifySignup(ctx context.Context, email string, handle []byte, jkt string, ceremony json.RawMessage, body []byte) (db.CreateWebauthnCredentialParams, error) {
	if ctx.Err() != nil {
		return db.CreateWebauthnCredentialParams{}, ctx.Err()
	}
	var frozen signupCeremony
	decoder := json.NewDecoder(bytes.NewReader(ceremony))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&frozen) != nil || decoder.Decode(new(any)) != io.EOF || frozen.Purpose != "registration" || frozen.JKT != jkt || jkt == "" || frozen.Email != email || !emailaddress.ValidCanonicalMailbox(email) || len(handle) != userHandleByteLen || !bytes.Equal(frozen.Session.UserID, handle) || frozen.Session.UserVerification != protocol.VerificationRequired || !s.now().Before(frozen.Expires) {
		return db.CreateWebauthnCredentialParams{}, ErrChallengeFlowMismatch
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return db.CreateWebauthnCredentialParams{}, ErrInvalidResponse
	}
	cred, err := s.wa.CreateCredential(newUserAdapter(db.User{Email: email}, handle, nil), frozen.Session, parsed)
	if err != nil {
		return db.CreateWebauthnCredentialParams{}, ErrVerification
	}
	if !cred.Flags.UserVerified || !cred.Flags.UserPresent {
		return db.CreateWebauthnCredentialParams{}, ErrUserVerificationRequired
	}
	if len(cred.ID) == 0 || len(cred.ID) > 1024 || len(cred.PublicKey) == 0 {
		return db.CreateWebauthnCredentialParams{}, ErrVerification
	}
	return credentialToCreateParams(db.User{}.ID, cred), nil
}
