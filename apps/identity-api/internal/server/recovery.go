package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type recoveryErrorResponse struct {
	Error string `json:"error"`
}

type recoveryVerifyRequest struct {
	Code string `json:"code"`
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
	Status    string `json:"status"`
	Remaining int    `json:"remaining"`
}

// registerRecoveryRoutes mounts the recovery (backup) code endpoints from
// docs/api-design.md §1.3. Generation and status are self-service management
// routes under /api/v1/auth/recovery-codes; the verify route lives under the
// MFA namespace (/api/v1/auth/mfa/verify-recovery-code) because it is an
// alternative second factor consumed during authentication. All three require a
// live session, so codes can only be minted for, inspected on, or consumed
// against the account the caller already holds a session for.
//
// NOTE: two enforcement gaps here are deliberately owned by the Step-up/ACR
// framework in Task 4.7, not by this task:
//
//  1. docs/api-design.md marks recovery-codes/generate as requiring Step-up
//     authentication (re-assert a strong factor before minting fresh codes).
//     That guard is deferred to Task 4.7, mirroring the same deferral on
//     DELETE /api/v1/users/me/phone; it will be layered onto the generate route
//     there without changing the handler.
//  2. docs/api-design.md §1.3 describes verify-recovery-code as a *login bypass*
//     — the factor a user presents when every passkey and the TOTP authenticator
//     are gone — which implies it must be reachable from a half-authenticated
//     (MFA-pending) state. No such state exists yet: session.Session carries no
//     ACR/AMR field, so there is no partial session to accept. Rather than
//     invent one here, the route requires a full session; Task 4.7 owns the
//     partial-session state and will widen acceptance at this layer only,
//     leaving recovery.Service untouched.
func (s *Server) registerRecoveryRoutes() {
	if s.deps.SessionManager == nil {
		s.logger.Warn("recovery: no session manager configured; recovery-code routes not mounted")
		return
	}

	guard, err := session.NewRequireSession(s.deps.SessionManager)
	if err != nil {
		s.logger.Error("recovery: failed to build RequireSession middleware", "error", err.Error())
		return
	}

	s.router.Route("/api/v1/auth/recovery-codes", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/generate", s.handleRecoveryGenerate())
		r.Get("/status", s.handleRecoveryStatus())
	})

	// The verify route is a distinct second factor rather than account
	// management, so it is namespaced alongside the other MFA verifiers.
	s.router.Route("/api/v1/auth/mfa/verify-recovery-code", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/", s.handleRecoveryVerify())
	})
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

		// r.RemoteAddr is the real client IP (middleware.RealIP resolved it from
		// the proxy headers), so the per-subnet limit groups by the genuine
		// source rather than the ingress address.
		result, err := s.deps.Recovery.Generate(r.Context(), userID, r.RemoteAddr)
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
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

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

		if err := s.deps.Recovery.Verify(r.Context(), userID, req.Code, r.RemoteAddr); err != nil {
			s.writeRecoveryError(w, "verify recovery code", err)
			return
		}

		// Surface the remaining count so a client can prompt regeneration as the
		// user burns through the batch. A count failure here must not undo the
		// successful consumption, so it degrades to omitting the number.
		remaining := 0
		if status, err := s.deps.Recovery.Status(r.Context(), userID); err == nil {
			remaining = status.Remaining
		}

		writeJSON(w, http.StatusOK, recoveryVerifyResponse{Status: "verified", Remaining: remaining})
	}
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
