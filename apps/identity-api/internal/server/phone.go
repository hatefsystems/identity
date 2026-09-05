package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

// phoneFactorSMS labels the factor in phone audit payloads, matching mfaFactorTOTP.
//
// No phone number, verification id, or code ever enters a payload: the number is
// PII held envelope-encrypted with only a blind index for lookup, so copying it
// into a Class C audit row (retained far longer, and readable by the DPO tooling)
// would defeat that. The account is already identified by actor_id.
const phoneFactorSMS = "sms"

type phoneErrorResponse struct {
	Error string `json:"error"`
}

type phoneSendCodeRequest struct {
	Phone string `json:"phone"`
}

type phoneVerifyRequest struct {
	VerificationID string `json:"verification_id"`
	Code           string `json:"code"`
}

type phoneSendCodeResponse struct {
	Status         string `json:"status"`
	VerificationID string `json:"verification_id"`
}

type phoneStatusResponse struct {
	Status string `json:"status"`
}

// registerPhoneRoutes mounts the SMS OTP phone-verification endpoints from
// docs/api-design.md §1.5. They live under the authenticated self-service
// surface (/api/v1/users/me/phone), so a valid session is required: a phone can
// only be attached to the account the caller already holds a live session for.
//
// Sending a code and deleting the verified phone additionally require a
// single-use Step-up grant. The grant middleware runs before the handler, so it
// is consumed before parsing input, touching rate limits, or dispatching SMS.
// Sensitive routes are left unmounted when no step-up service is configured
// rather than served ungated; verification remains session-only because the
// pending challenge is itself bound to the exact initiating session.
func (s *Server) registerPhoneRoutes() {
	guard, ok := s.sessionGuard("smsotp")
	if !ok {
		return
	}
	stepGuard, hasStepUp := s.stepUpGuard("smsotp")

	s.router.Route("/api/v1/users/me/phone", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/verify", s.handlePhoneVerify())

		if !hasStepUp {
			return
		}
		r.Group(func(pr chi.Router) {
			pr.Use(stepGuard.Handler)
			pr.Post("/send-code", s.handlePhoneSendCode())
			pr.Delete("/", s.handlePhoneRemove())
		})
	})
}

// handlePhoneSendCode serves POST /api/v1/users/me/phone/send-code. It issues a
// 6-digit SMS OTP subject to the independent per-phone and per-subnet rate
// limits and the brute-force lockout. The response is deliberately uniform on
// success so it never reveals whether a code was actually dispatched.
func (s *Server) handlePhoneSendCode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}
		current, ok := session.FromContext(r.Context())
		if !ok {
			s.logger.Error("smsotp: send-code handler reached without a session in context")
			writeJSON(w, http.StatusInternalServerError, phoneErrorResponse{Error: "server_error"})
			return
		}

		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req phoneSendCodeRequest
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, phoneErrorResponse{Error: "invalid_request"})
				return
			}
		}

		verificationID, err := s.deps.SMSOTP.SendCode(
			r.Context(), userID, current.ID, req.Phone, clientip.FromRequest(r),
		)
		if err != nil {
			s.writePhoneError(w, "send phone code", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, phoneSendCodeResponse{
			Status:         "sent",
			VerificationID: verificationID,
		})
	}
}

// handlePhoneVerify serves POST /api/v1/users/me/phone/verify. On a correct code
// it persists the envelope-encrypted phone and its blind index and marks the
// phone verified; on repeated failures it enforces the 3-attempt lockout.
func (s *Server) handlePhoneVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}
		current, ok := session.FromContext(r.Context())
		if !ok {
			s.logger.Error("smsotp: verify handler reached without a session in context")
			writeJSON(w, http.StatusInternalServerError, phoneErrorResponse{Error: "server_error"})
			return
		}

		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req phoneVerifyRequest
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, phoneErrorResponse{Error: "invalid_request"})
				return
			}
		}

		if err := s.deps.SMSOTP.Verify(r.Context(), userID, current.ID, req.VerificationID, req.Code); err != nil {
			s.writePhoneError(w, "verify phone code", err)
			return
		}

		// Binding a phone adds a recovery/second factor, so it is ledgered (Class B)
		// like the MFA and passkey enrolments. Verify enables it exactly once per
		// verification record, so this cannot double-record on retry.
		s.record(r, audit.Event{
			EventType:    audit.EventPhoneVerified,
			ActionStatus: audit.StatusSuccess,
			ActorID:      userID,
			SubjectID:    &userID,
			Payload:      map[string]any{"factor": phoneFactorSMS},
			Security:     &audit.SecurityContext{AccountRef: userID},
		})
		writeJSON(w, http.StatusOK, phoneStatusResponse{Status: "verified"})
	}
}

// handlePhoneRemove serves DELETE /api/v1/users/me/phone. It clears the verified
// phone and its blind index together. Step-up gated: see registerPhoneRoutes.
//
// Removing a phone that is not set is a no-op success, so the endpoint is
// idempotent and a client retrying after a dropped response does not see a
// spurious failure.
func (s *Server) handlePhoneRemove() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		removed, err := s.deps.SMSOTP.RemovePhone(r.Context(), userID)
		if err != nil {
			s.writePhoneError(w, "remove phone", err)
			return
		}

		// Only a real state change is ledgered. The endpoint is idempotent, so a
		// retry after a dropped response still returns 204 with removed == false;
		// recording that would put a second Class B row in the chain asserting a
		// factor was torn down that was already gone.
		if removed {
			s.record(r, audit.Event{
				EventType:    audit.EventPhoneRemoved,
				ActionStatus: audit.StatusSuccess,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload:      map[string]any{"factor": phoneFactorSMS},
				Security:     &audit.SecurityContext{AccountRef: userID},
			})
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// writePhoneError maps domain SMS OTP errors to HTTP responses. Rate-limit and
// lockout conditions return 429 so a client can back off; validation problems
// return 400; a missing account maps to 401.
func (s *Server) writePhoneError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, smsotp.ErrUserNotFound), errors.Is(err, smsotp.ErrAccountNotActive):
		writeJSON(w, http.StatusUnauthorized, phoneErrorResponse{Error: "unauthorized"})
	case errors.Is(err, smsotp.ErrInvalidPhone):
		writeJSON(w, http.StatusBadRequest, phoneErrorResponse{Error: "invalid_phone"})
	case errors.Is(err, smsotp.ErrRateLimited):
		writeJSON(w, http.StatusTooManyRequests, phoneErrorResponse{Error: "rate_limited"})
	case errors.Is(err, smsotp.ErrLockedOut):
		writeJSON(w, http.StatusTooManyRequests, phoneErrorResponse{Error: "locked_out"})
	case errors.Is(err, smsotp.ErrNoActiveCode):
		writeJSON(w, http.StatusBadRequest, phoneErrorResponse{Error: "no_active_code"})
	case errors.Is(err, smsotp.ErrInvalidCode):
		writeJSON(w, http.StatusBadRequest, phoneErrorResponse{Error: "invalid_code"})
	default:
		s.logger.Error("smsotp: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, phoneErrorResponse{Error: "server_error"})
	}
}
