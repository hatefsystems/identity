package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// mfaFactorTOTP labels the factor in audit payloads. The MFA package currently
// implements only TOTP, but WebAuthn is already a second factor elsewhere in the
// system, so every MFA event names its factor rather than leaving readers to infer
// it from the event type.
const mfaFactorTOTP = "totp"

type mfaErrorResponse struct {
	Error string `json:"error"`
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
// Starting enrollment and disabling TOTP both require Step-up authentication.
// Enrollment completion does not consume a second grant: it can only redeem the
// short-lived pending record bound to the same user and initiating session.
func (s *Server) registerMFARoutes() {
	guard, ok := s.sessionGuard("mfa")
	if !ok {
		return
	}
	stepGuard, hasStepUp := s.stepUpGuard("mfa")

	s.router.Route("/api/v1/auth/mfa", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/verify", s.handleMFAVerify())

		if !hasStepUp {
			return
		}
		// The grant is consumed at enrollment start. Verification relies on the
		// pending enrollment's exact session binding.
		r.Group(func(pr chi.Router) {
			pr.Use(stepGuard.Handler)
			pr.Post("/generate", s.handleMFAGenerate())
			pr.Delete("/", s.handleMFADisable())
		})
	})
}

// handleMFAGenerate serves POST /api/v1/auth/mfa/generate.
// Generates a fresh TOTP secret, stores its envelope-encrypted payload,
// and returns the setup secret and otpauth:// URI.
func (s *Server) handleMFAGenerate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		current, _ := session.FromContext(r.Context())
		resp, err := s.deps.MFA.GenerateSetup(r.Context(), userID, current.ID)
		if err != nil {
			s.writeMFAError(w, "generate mfa setup", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleMFAVerify serves POST /api/v1/auth/mfa/verify.
// Verifies the submitted 6-digit passcode against the pending secret and enables MFA.
func (s *Server) handleMFAVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req mfaVerifyRequest
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_request"})
				return
			}
		}

		current, _ := session.FromContext(r.Context())
		if err := s.deps.MFA.VerifyAndEnable(r.Context(), userID, current.ID, req.EnrollmentID, req.Code); err != nil {
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

		if err := s.deps.MFA.Disable(r.Context(), userID); err != nil {
			s.writeMFAError(w, "disable mfa", err)
			return
		}

		// Removing a factor weakens the account, so this is ledgered (Class B) the
		// same way enabling one is. ErrLastFactor keeps this from being an
		// account-takeover lockout path, but a successful disable is exactly what an
		// attacker who already holds a session would do next.
		s.record(r, audit.Event{
			EventType:    audit.EventMFATOTPDisabled,
			ActionStatus: audit.StatusSuccess,
			ActorID:      userID,
			SubjectID:    &userID,
			Payload:      map[string]any{"factor": mfaFactorTOTP},
			Security:     &audit.SecurityContext{AccountRef: userID},
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// writeMFAError maps domain MFA errors into standard HTTP responses.
func (s *Server) writeMFAError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, mfa.ErrUserNotFound):
		writeJSON(w, http.StatusUnauthorized, mfaErrorResponse{Error: "unauthorized"})
	case errors.Is(err, mfa.ErrAccountNotActive):
		writeJSON(w, http.StatusUnauthorized, mfaErrorResponse{Error: "unauthorized"})
	case errors.Is(err, mfa.ErrLastFactor):
		writeJSON(w, http.StatusConflict, mfaErrorResponse{Error: "last_factor"})
	case errors.Is(err, mfa.ErrMfaAlreadyEnabled):
		writeJSON(w, http.StatusConflict, mfaErrorResponse{Error: "mfa_already_enabled"})
	case errors.Is(err, mfa.ErrMfaNotSetup):
		writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "mfa_not_setup"})
	case errors.Is(err, mfa.ErrEnrollmentExpired):
		writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "enrollment_expired"})
	case errors.Is(err, mfa.ErrInvalidCode):
		writeJSON(w, http.StatusBadRequest, mfaErrorResponse{Error: "invalid_code"})
	default:
		s.logger.Error("mfa: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, mfaErrorResponse{Error: "server_error"})
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
