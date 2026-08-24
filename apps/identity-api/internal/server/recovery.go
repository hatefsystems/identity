package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type recoveryErrorResponse struct {
	Error string `json:"error"`
}

type recoveryVerifyRequest struct {
	TransactionID string `json:"transaction_id"`
	Code          string `json:"code"`
}

type recoveryStartRequest struct {
	Email string `json:"email"`
}

type recoveryStartResponse struct {
	TransactionID string    `json:"transaction_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	ExpiresIn     int       `json:"expires_in"`
}

// recoveryGenerateResponse is the one-time batch returned by the generate
// endpoint. The plaintext codes appear here and nowhere else server-side; the
// database holds only their hashes.
type recoveryGenerateResponse struct {
	Codes []string `json:"codes"`
	Count int      `json:"count"`
}

// recoveryStatusResponse reports how many unused codes remain.
type recoveryStatusResponse struct {
	Remaining int  `json:"remaining"`
	Low       bool `json:"low"`
}

type recoveryVerifyResponse struct {
	Next      string `json:"next"`
	ExpiresIn int    `json:"expires_in"`
}

// registerRecoveryRoutes mounts the recovery (backup) code endpoints from
// docs/api-design.md §1.3. Generation and status are self-service management
// routes under /api/v1/auth/recovery-codes; the verify route lives under the
// MFA namespace (/api/v1/auth/mfa/verify-recovery-code) because it is an
// anonymous recovery alternative. A normal authenticated session protects only
// management (generate/status); start and verify intentionally run without one
// and can mint only a restricted recovery-enrollment session.
//
// POST /generate additionally requires a Step-up grant: a fresh batch of codes is
// a set of long-lived bypasses for every other factor, so minting one must cost a
// re-asserted strong factor. It is left unmounted when no step-up service is
// configured, rather than served ungated. Note that recovery codes are
// deliberately not accepted *as* a step-up factor (see internal/stepup), which
// keeps this from being circular: a stolen code cannot mint the grant needed to
// replace the batch.
//
// Successful verification consumes the code and permits exactly one UV passkey
// enrollment through the dedicated /api/v1/auth/enrollment/webauthn routes. It
// never promotes the restricted session; the replacement credential must then
// be used for a fresh login.
func (s *Server) registerRecoveryRoutes() {
	if s.deps.RecoveryFlow != nil && s.deps.SessionManager != nil {
		s.router.Post("/api/v1/auth/recovery/start", s.handleRecoveryStart())
		s.router.Post("/api/v1/auth/mfa/verify-recovery-code", s.handleRecoveryVerify())
	}
	if s.deps.Recovery == nil {
		return
	}

	guard, ok := s.sessionGuard("recovery")
	if !ok {
		return
	}
	stepGuard, hasStepUp := s.stepUpGuard("recovery")

	s.router.Route("/api/v1/auth/recovery-codes", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Get("/status", s.handleRecoveryStatus())

		if !hasStepUp {
			return
		}
		r.Group(func(pr chi.Router) {
			pr.Use(stepGuard.Handler)
			pr.Post("/generate", s.handleRecoveryGenerate())
		})
	})
}

// handleRecoveryStart creates a single-use opaque recovery transaction. Real,
// inactive, deleted, and unknown accounts all receive the same 202 shape.
func (s *Server) handleRecoveryStart() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}
		var req recoveryStartRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, recoveryErrorResponse{Error: "invalid_request"})
			return
		}
		result, err := s.deps.RecoveryFlow.Start(r.Context(), req.Email)
		if err != nil {
			s.logger.Error("recovery: start failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, recoveryErrorResponse{Error: "server_error"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusAccepted, recoveryStartResponse{
			TransactionID: result.TransactionID,
			ExpiresAt:     result.ExpiresAt,
			ExpiresIn:     int(recovery.RecoveryTransactionTTL.Seconds()),
		})
	}
}

// handleRecoveryGenerate serves POST /api/v1/auth/recovery-codes/generate.
// It mints a fresh batch (atomically destroying any previous one) and returns
// the plaintext codes exactly once. The response is marked no-store so the
// secrets are never written to a shared or disk cache.
func (s *Server) handleRecoveryGenerate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		result, err := s.deps.Recovery.Generate(r.Context(), userID, clientip.FromRequest(r))
		if err != nil {
			s.writeRecoveryError(w, "generate recovery codes", err)
			return
		}

		// These are one-time secrets: keep them out of any intermediary or
		// browser cache so a shared cache or back-button cannot resurface them.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, recoveryGenerateResponse{
			Codes: result.Codes,
			Count: result.Count,
		})
	}
}

// handleRecoveryStatus serves GET /api/v1/auth/recovery-codes/status, reporting
// how many unused codes remain and whether the account is running low.
func (s *Server) handleRecoveryStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		status, err := s.deps.Recovery.Status(r.Context(), userID)
		if err != nil {
			s.writeRecoveryError(w, "recovery code status", err)
			return
		}

		writeJSON(w, http.StatusOK, recoveryStatusResponse{
			Remaining: status.Remaining,
			Low:       status.Low,
		})
	}
}

// handleRecoveryVerify serves POST /api/v1/auth/mfa/verify-recovery-code. On a
// correct code the matching row is consumed (physically deleted) in the same
// atomic transaction as the lookup, so a code cannot be replayed. Every code
// failure returns an opaque 401 so nothing distinguishes a wrong, spent, or
// foreign code.
func (s *Server) handleRecoveryVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req recoveryVerifyRequest
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, recoveryErrorResponse{Error: "invalid_request"})
				return
			}
		}

		userID, err := s.deps.RecoveryFlow.Verify(r.Context(), req.TransactionID, req.Code, clientip.FromRequest(r))
		if err != nil {
			s.writeRecoveryFlowError(w, err)
			return
		}

		if _, err := s.deps.SessionManager.Issue(w, session.IssueParams{
			UserID:    userID.String(),
			IP:        clientip.FromRequest(r),
			UserAgent: r.UserAgent(),
			Kind:      session.KindRecoveryEnrollment,
		}); err != nil {
			// The code has already been physically deleted. Fail closed rather
			// than attempting to resurrect a credential after session failure.
			s.logger.Error("recovery: issue restricted session after consumed code failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, recoveryErrorResponse{Error: "server_error"})
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, recoveryVerifyResponse{
			Next:      "enroll_factor",
			ExpiresIn: int(session.RecoveryEnrollmentTTL.Seconds()),
		})
	}
}

func (s *Server) writeRecoveryFlowError(w http.ResponseWriter, err error) {
	if errors.Is(err, recovery.ErrRateLimited) {
		writeJSON(w, http.StatusTooManyRequests, recoveryErrorResponse{Error: "rate_limited"})
		return
	}
	if errors.Is(err, recovery.ErrInvalidCode) || errors.Is(err, recovery.ErrUserNotFound) || errors.Is(err, recovery.ErrAccountNotActive) {
		writeJSON(w, http.StatusUnauthorized, recoveryErrorResponse{Error: "invalid_credentials"})
		return
	}
	s.logger.Error("recovery: verify flow failed", "error", err.Error())
	writeJSON(w, http.StatusInternalServerError, recoveryErrorResponse{Error: "server_error"})
}

// writeRecoveryError maps domain recovery errors to HTTP responses. A bad code
// is an opaque 401 that never reveals why it failed (unknown, spent, or foreign
// all render identically), a saturated limit is 429, and a missing or
// non-active account is an equally opaque 401 — surfacing "suspended" here would
// turn account state into an oracle, matching writeWebAuthnLoginError.
func (s *Server) writeRecoveryError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, recovery.ErrUserNotFound),
		errors.Is(err, recovery.ErrAccountNotActive):
		writeJSON(w, http.StatusUnauthorized, recoveryErrorResponse{Error: "unauthorized"})
	case errors.Is(err, recovery.ErrInvalidCode):
		writeJSON(w, http.StatusUnauthorized, recoveryErrorResponse{Error: "invalid_code"})
	case errors.Is(err, recovery.ErrRateLimited):
		writeJSON(w, http.StatusTooManyRequests, recoveryErrorResponse{Error: "rate_limited"})
	default:
		s.logger.Error("recovery: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, recoveryErrorResponse{Error: "server_error"})
	}
}
