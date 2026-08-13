package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

type phoneErrorResponse struct {
	Error string `json:"error"`
}

type phoneSendCodeRequest struct {
	Phone string `json:"phone"`
}

type phoneVerifyRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type phoneStatusResponse struct {
	Status string `json:"status"`
}

// registerPhoneRoutes mounts the SMS OTP phone-verification endpoints from
// docs/api-design.md §1.5. They live under the authenticated self-service
// surface (/api/v1/users/me/phone), so a valid session is required: a phone can
// only be attached to the account the caller already holds a live session for.
//
// DELETE /api/v1/users/me/phone is intentionally NOT mounted here: removing a
// verified phone requires Step-up authentication (X-Step-Up-Auth), which lands
// with the Step-up framework in Task 4.7.
func (s *Server) registerPhoneRoutes() {
	if s.deps.SessionManager == nil {
		s.logger.Warn("smsotp: no session manager configured; phone routes not mounted")
		return
	}

	guard, err := session.NewRequireSession(s.deps.SessionManager)
	if err != nil {
		s.logger.Error("smsotp: failed to build RequireSession middleware", "error", err.Error())
		return
	}

	s.router.Route("/api/v1/users/me/phone", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/send-code", s.handlePhoneSendCode())
		r.Post("/verify", s.handlePhoneVerify())
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

		// r.RemoteAddr is the real client IP: middleware.RealIP has already
		// resolved it from the proxy headers, so the per-subnet limit groups by
		// the genuine source rather than the ingress address.
		if err := s.deps.SMSOTP.SendCode(r.Context(), userID, req.Phone, r.RemoteAddr); err != nil {
			s.writePhoneError(w, "send phone code", err)
			return
		}

		writeJSON(w, http.StatusOK, phoneStatusResponse{Status: "sent"})
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

		if err := s.deps.SMSOTP.Verify(r.Context(), userID, req.Phone, req.Code); err != nil {
			s.writePhoneError(w, "verify phone code", err)
			return
		}

		writeJSON(w, http.StatusOK, phoneStatusResponse{Status: "verified"})
	}
}

// writePhoneError maps domain SMS OTP errors to HTTP responses. Rate-limit and
// lockout conditions return 429 so a client can back off; validation problems
// return 400; a missing account maps to 401.
func (s *Server) writePhoneError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, smsotp.ErrUserNotFound):
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
