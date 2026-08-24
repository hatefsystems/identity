package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

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
			s.writeMFAError(w, "verify and enable mfa", err)
			return
		}

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
