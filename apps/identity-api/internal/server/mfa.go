package server

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

// mfaFactorTOTP labels the factor in audit payloads. The MFA package currently
// implements only TOTP, but WebAuthn is already a second factor elsewhere in the
// system, so every MFA event names its factor rather than leaving readers to infer
// it from the event type.
const mfaFactorTOTP = "totp"

type mfaErrorResponse struct {
	Error     string `json:"error"`
	ACRValues string `json:"acr_values,omitempty"`
}

type mfaVerifyRequest struct {
	EnrollmentID string `json:"enrollment_id"`
	Code         string `json:"code"`
}

type mfaStatusResponse struct {
	Status string `json:"status"`
}

// registerMFARoutes mounts the TOTP MFA management endpoints from
// docs/api-design.md §1.3.
//
// Starting enrollment accepts UV Step-up or a purpose-specific password/contact proof.
// Disabling TOTP accepts only fresh enrolled-TOTP or UV Step-up.
// Enrollment completion does not consume a second grant: it can only redeem the
// short-lived pending record bound to the same user and initiating session.
func (s *Server) registerMFARoutes() {
	guard, ok := s.sessionGuard("mfa")
	if !ok {
		return
	}
	s.deps.MFA.SetSessions(s.deps.SessionManager)

	s.router.Route("/api/v1/auth/mfa", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/verify", s.handleMFAVerify())

		if s.deps.StepUp != nil || s.deps.MFAEnrollmentProofs != nil {
			r.Post("/generate", s.handleMFAGenerate())
		}
		if s.deps.StepUp != nil {
			r.Delete("/", s.handleMFADisable())
		}
	})
}

// handleMFAGenerate serves POST /api/v1/auth/mfa/generate.
// Generates a fresh TOTP secret, stores its envelope-encrypted payload,
// and returns the setup secret and otpauth:// URI.
func (s *Server) handleMFAGenerate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		current, _ := session.FromContext(r.Context())
		if !current.AuthVersionSet {
			s.writeMFAError(w, "generate mfa setup", mfa.ErrAccountNotActive)
			return
		}
		if !emptyMFARequest(r) {
			writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_request"})
			return
		}
		auth, err := s.mfaAuthorization(r, current, true)
		if err != nil {
			s.writeMFAError(w, "authorize mfa setup", err)
			return
		}
		resp, err := s.deps.MFA.GenerateSetup(r.Context(), current, auth)
		if err != nil {
			s.writeMFAError(w, "generate mfa setup", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, resp)
	}
}

func emptyMFARequest(r *http.Request) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	return err == nil && len(body) == 0
}

func (s *Server) mfaAuthorization(r *http.Request, sess session.Session, start bool) (mfa.Authorization, error) {
	grants, proofs := r.Header.Values(stepup.HeaderStepUpAuth), r.Header.Values("X-Action-Proof")
	if len(grants)+len(proofs) != 1 || !start && len(proofs) != 0 {
		return mfa.Authorization{}, mfa.ErrUnauthorized
	}
	if len(proofs) == 1 {
		if len(proofs[0]) != 43 || s.deps.MFAEnrollmentProofs == nil {
			return mfa.Authorization{}, mfa.ErrUnauthorized
		}
		raw, err := base64.RawURLEncoding.DecodeString(proofs[0])
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != proofs[0] {
			return mfa.Authorization{}, mfa.ErrUnauthorized
		}
		return mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: proofs[0]}, nil
	}
	if grants[0] == "" || len(grants[0]) > 16*1024 || strings.Contains(grants[0], ",") || s.deps.StepUp == nil {
		return mfa.Authorization{}, mfa.ErrUnauthorized
	}
	grant, err := s.deps.StepUp.Validate(r.Context(), grants[0], sess)
	if err != nil {
		return mfa.Authorization{}, err
	}
	method := ""
	if slices.Contains(grant.AMR, "hwk") && slices.Contains(grant.AMR, "user") {
		method = mfa.AuthorizationWebAuthnUV
	} else if !start && slices.Contains(grant.AMR, "otp") {
		method = mfa.AuthorizationTOTP
	}
	if method == "" || !grant.AuthVersionSet {
		return mfa.Authorization{}, mfa.ErrUnauthorized
	}
	return mfa.Authorization{UserID: grant.UserID, SessionID: grant.SessionID, JKT: grant.DPoPJKT, AuthVersion: grant.AuthVersion, Method: method, ExpiresAt: grant.ExpiresAt}, nil
}

// handleMFAVerify serves POST /api/v1/auth/mfa/verify.
// Verifies the submitted 6-digit passcode against the pending secret and enables MFA.
func (s *Server) handleMFAVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		if len(r.Header.Values(stepup.HeaderStepUpAuth))+len(r.Header.Values("X-Action-Proof")) != 0 {
			s.writeMFAError(w, "misplaced mfa authority", mfa.ErrUnauthorized)
			return
		}
		values, ok := readProofStringObject(r, []string{"enrollment_id", "code"})
		if !ok {
			writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_request"})
			return
		}
		id, parseErr := uuid.Parse(values["enrollment_id"])
		_, codeErr := totp.CanonicalizeCode(values["code"])
		if parseErr != nil || id == uuid.Nil || id.String() != values["enrollment_id"] || codeErr != nil {
			writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_request"})
			return
		}

		current, _ := session.FromContext(r.Context())
		if !current.AuthVersionSet {
			s.writeMFAError(w, "verify and enable mfa", mfa.ErrAccountNotActive)
			return
		}
		if err := s.deps.MFA.VerifyAndEnable(r.Context(), current, values["enrollment_id"], values["code"]); err != nil {
			if errors.Is(err, mfa.ErrOutcomeUnknown) {
				s.writeMFAError(w, "verify and enable mfa", err)
				return
			}
			s.record(r, audit.Event{
				EventType:    audit.EventMFAVerifyFailed,
				ActionStatus: audit.StatusFailure,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload: map[string]any{
					"factor": mfaFactorTOTP,
					"reason": mfaFailureReason(err),
				},
			})
			s.writeMFAError(w, "verify and enable mfa", err)
			return
		}
		session.SecurityChangeCommitted(r.Context())

		// This endpoint is enrolment-completing: reaching here means TOTP went from
		// "pending secret" to "required at login", which is the state change worth
		// ledgering. A repeat call cannot re-record it — ErrMfaAlreadyEnabled sends it
		// down the failure path above.
		s.record(r, audit.Event{
			EventType:    audit.EventMFATOTPEnabled,
			ActionStatus: audit.StatusSuccess,
			ActorID:      userID,
			SubjectID:    &userID,
			Payload:      map[string]any{"factor": mfaFactorTOTP},
			Security:     &audit.SecurityContext{AccountRef: userID},
		})
		writeJSON(w, http.StatusOK, mfaStatusResponse{Status: "enabled"})
	}
}

// handleMFADisable serves DELETE /api/v1/auth/mfa.
// Disables TOTP MFA and wipes the stored secret.
func (s *Server) handleMFADisable() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		current, _ := session.FromContext(r.Context())
		if !current.AuthVersionSet {
			s.writeMFAError(w, "disable mfa", mfa.ErrAccountNotActive)
			return
		}
		if !emptyMFARequest(r) {
			writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_request"})
			return
		}
		auth, err := s.mfaAuthorization(r, current, false)
		if err != nil {
			s.writeMFAError(w, "authorize mfa disable", err)
			return
		}
		changed, err := s.deps.MFA.Disable(r.Context(), current, auth)
		if err != nil {
			s.writeMFAError(w, "disable mfa", err)
			return
		}

		// Removing a factor weakens the account, so this is ledgered (Class B) the
		// same way enabling one is. ErrLastFactor keeps this from being an
		// account-takeover lockout path, but a successful disable is exactly what an
		// attacker who already holds a session would do next.
		if changed {
			s.record(r, audit.Event{
				EventType:    audit.EventMFATOTPDisabled,
				ActionStatus: audit.StatusSuccess,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload:      map[string]any{"factor": mfaFactorTOTP},
				Security:     &audit.SecurityContext{AccountRef: userID},
			})
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// writeMFAError maps domain MFA errors into standard HTTP responses.
func (s *Server) writeMFAError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, mfa.ErrOutcomeUnknown), errors.Is(err, actionproof.ErrOutcomeUnknown):
		writeJSON(w, http.StatusServiceUnavailable, mfaErrorResponse{Error: "outcome_unknown"})
	case errors.Is(err, mfa.ErrUnauthorized), errors.Is(err, actionproof.ErrInvalid), errors.Is(err, actionproof.ErrUnauthorized), errors.Is(err, actionproof.ErrMFAEnrollmentExpired), errors.Is(err, session.ErrSessionNotFound), errors.Is(err, stepup.ErrNoGrant), errors.Is(err, stepup.ErrInvalidGrant), errors.Is(err, stepup.ErrGrantConsumed), errors.Is(err, stepup.ErrGrantNotForSession):
		writeJSON(w, http.StatusForbidden, mfaErrorResponse{Error: "insufficient_user_authentication", ACRValues: stepup.ACRStepUp})
	case errors.Is(err, mfa.ErrUserNotFound):
		writeJSON(w, http.StatusUnauthorized, mfaErrorResponse{Error: "unauthorized"})
	case errors.Is(err, mfa.ErrAccountNotActive):
		writeJSON(w, http.StatusUnauthorized, mfaErrorResponse{Error: "unauthorized"})
	case errors.Is(err, mfa.ErrLastFactor):
		writeJSON(w, http.StatusConflict, mfaErrorResponse{Error: "last_factor"})
	case errors.Is(err, accountpolicy.ErrLastFactor):
		writeJSON(w, http.StatusConflict, mfaErrorResponse{Error: "last_factor"})
	case errors.Is(err, accountpolicy.ErrLastCredential):
		writeJSON(w, http.StatusConflict, mfaErrorResponse{Error: "last_credential"})
	case errors.Is(err, mfa.ErrMfaAlreadyEnabled):
		writeJSON(w, http.StatusConflict, mfaErrorResponse{Error: "mfa_already_enabled"})
	case errors.Is(err, mfa.ErrMfaNotSetup):
		writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "mfa_not_setup"})
	case errors.Is(err, mfa.ErrEnrollmentExpired):
		writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "enrollment_expired"})
	case errors.Is(err, mfa.ErrInvalidCode):
		writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_code"})
	default:
		s.logger.Error("mfa: " + op + " failed")
		writeJSON(w, http.StatusServiceUnavailable, mfaErrorResponse{Error: "temporarily_unavailable"})
	}
}

// mfaFailureReason maps an enrollment-verification error to a stable, bounded audit
// label.
//
// The labels are deliberately the same vocabulary as the wire-level error codes in
// writeMFAError: a DPO correlating an audit record with a client-reported failure
// should not have to translate between two naming schemes. They stay a separate
// switch because the wire contract and the audit contract are versioned
// independently — an HTTP code may be broadened for privacy without collapsing the
// forensic distinction, and the internal_error bucket must never carry err.Error()
// into a Class C row.
func mfaFailureReason(err error) string {
	switch {
	case errors.Is(err, mfa.ErrInvalidCode):
		return "invalid_code"
	case errors.Is(err, mfa.ErrEnrollmentExpired):
		return "enrollment_expired"
	case errors.Is(err, mfa.ErrMfaNotSetup):
		return "mfa_not_setup"
	case errors.Is(err, mfa.ErrMfaAlreadyEnabled):
		return "mfa_already_enabled"
	case errors.Is(err, mfa.ErrUserNotFound), errors.Is(err, mfa.ErrAccountNotActive):
		return "unauthorized"
	default:
		return "internal_error"
	}
}
