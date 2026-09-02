package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
)

// privacyErrorResponse is the minimal JSON error envelope for the GDPR privacy
// routes. The codes are deliberately coarse: the reclaim endpoints never reveal
// which check failed.
type privacyErrorResponse struct {
	Error string `json:"error"`
}

// privacyReclaimRequest is the body of both reclaim endpoints. Token is required;
// Factor, Assertion, and Code are only read by the verify endpoint.
type privacyReclaimRequest struct {
	// Token is the plaintext single-use reclaim token from the notification email.
	Token string `json:"token"`
	// Factor names the presented factor: "webauthn" or "totp".
	Factor string `json:"factor"`
	// Assertion is the raw navigator.credentials.get() response for the WebAuthn
	// factor. It is kept as RawMessage so it can be handed to the WebAuthn parser
	// byte-for-byte rather than re-serialised.
	Assertion json.RawMessage `json:"assertion"`
	// Code is the passcode for the TOTP factor.
	Code string `json:"code"`
}

// privacyReclaimOptionsResponse tells the client which single factor to present.
// Exactly one is named; the response never enumerates the account's factors.
type privacyReclaimOptionsResponse struct {
	Factor   string                        `json:"factor"`
	WebAuthn *protocol.CredentialAssertion `json:"webauthn,omitempty"`
}

// registerPrivacyRoutes mounts the GDPR "Right to be Forgotten" endpoints from
// docs/api-design.md §1.4. It is only called when a privacy service is configured
// (Deps.Privacy != nil), which by the fail-closed notification contract means a
// real notifier exists — a deletion whose reclaim token cannot be delivered has no
// recovery window, so the routes stay absent rather than accept such a request.
//
// DELETE /api/v1/users/me is gated behind RequireSession *then* RequireStepUp, in
// that order: the step-up middleware validates the grant against the caller's live
// session, so a session in context is its precondition, not something it
// establishes. Following the Deps.StepUp contract, an unavailable step-up service
// leaves the route unmounted rather than served ungated.
//
// The two reclaim endpoints are anonymous and token-bearing, and are mounted
// outside the session group. They deliberately do not live under /users/me: that
// prefix implies a session, and there is none — the account is pending_deletion and
// cannot log in at all, which is the whole reason the reclaim ceremony exists.
func (s *Server) registerPrivacyRoutes() {
	s.router.Route("/api/v1/auth/deletion/reclaim", func(r chi.Router) {
		r.Post("/options", s.handlePrivacyReclaimOptions())
		r.Post("/", s.handlePrivacyReclaim())
	})

	guard, hasSession := s.sessionGuard("privacy")
	if !hasSession {
		return
	}
	stepGuard, hasStepUp := s.stepUpGuard("privacy")
	if !hasStepUp {
		return
	}

	s.router.Route("/api/v1/users/me", func(r chi.Router) {
		r.Use(guard.Handler)
		r.With(stepGuard.Handler).Delete("/", s.handlePrivacyRequestDeletion())
	})
}

// handlePrivacyRequestDeletion serves DELETE /api/v1/users/me.
//
// It answers 204 both for a first request and for an idempotent repeat, so a client
// that retries after a dropped response cannot tell the difference and cannot use
// the endpoint to probe prior account state.
//
// Note the residual authority this leaves: every stateful session and refresh-token
// family is revoked synchronously, but an access token already issued to a
// downstream client stays valid until it expires — at most the 10-minute
// access-token TTL. There is no revocation epoch and no per-request status re-read
// yet, so callers must not assume instantaneous cutoff across the ecosystem.
func (s *Server) handlePrivacyRequestDeletion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		if _, err := s.deps.Privacy.RequestDeletion(r.Context(), userID, clientip.FromRequest(r)); err != nil {
			switch {
			case errors.Is(err, privacy.ErrRateLimited):
				writeJSON(w, http.StatusTooManyRequests, privacyErrorResponse{Error: "rate_limited"})
			case errors.Is(err, privacy.ErrUserNotFound):
				// The session outlived its account.
				writeJSON(w, http.StatusUnauthorized, privacyErrorResponse{Error: "unauthorized"})
			default:
				s.logger.Error("privacy: deletion request failed", "error", err.Error())
				writeJSON(w, http.StatusInternalServerError, privacyErrorResponse{Error: "server_error"})
			}
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

// handlePrivacyReclaimOptions serves POST /api/v1/auth/deletion/reclaim/options.
// It resolves the emailed token and names the single factor to present, without
// consuming the token — a user who abandons the ceremony halfway must still be able
// to restart it.
func (s *Server) handlePrivacyReclaimOptions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := s.readPrivacyReclaimRequest(w, r)
		if !ok {
			return
		}

		challenge, err := s.deps.Privacy.ReclaimOptions(r.Context(), req.Token, clientip.FromRequest(r))
		if err != nil {
			s.writePrivacyReclaimError(w, "reclaim options", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, privacyReclaimOptionsResponse{
			Factor:   challenge.Factor,
			WebAuthn: challenge.WebAuthn,
		})
	}
}

// handlePrivacyReclaim serves POST /api/v1/auth/deletion/reclaim. On success the
// account returns to active and every outstanding reclaim token for it is
// invalidated; the response is 204 and carries no session — the user must now log
// in normally.
func (s *Server) handlePrivacyReclaim() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := s.readPrivacyReclaimRequest(w, r)
		if !ok {
			return
		}

		err := s.deps.Privacy.Reclaim(r.Context(), req.Token, privacy.ReclaimAttempt{
			Method:    req.Factor,
			Assertion: req.Assertion,
			Code:      req.Code,
			ClientIP:  clientip.FromRequest(r),
		})
		if err != nil {
			s.writePrivacyReclaimError(w, "reclaim", err)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

// readPrivacyReclaimRequest reads and decodes a size-capped reclaim body, reusing
// the WebAuthn body cap because the assertion it may carry is the largest
// legitimate payload.
//
// An empty body decodes to a zero-valued request rather than a 400, so a missing
// token follows the same opaque 401 path as a wrong one.
func (s *Server) readPrivacyReclaimRequest(w http.ResponseWriter, r *http.Request) (privacyReclaimRequest, bool) {
	body, ok := s.readWebAuthnBody(w, r)
	if !ok {
		return privacyReclaimRequest{}, false
	}

	var req privacyReclaimRequest
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, privacyErrorResponse{Error: "invalid_request"})
			return privacyReclaimRequest{}, false
		}
	}
	return req, true
}

// writePrivacyReclaimError maps a reclaim failure to a response.
//
// Every token, factor, account-state, and factor-availability failure renders as
// the identical opaque 401: these endpoints are anonymous, so any distinction would
// confirm that a given deletion exists or disclose which factors the account holds.
// Only a saturated rate limit (429) and a genuine infrastructure fault (500) are
// distinguishable, and neither depends on the token's validity.
func (s *Server) writePrivacyReclaimError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, privacy.ErrRateLimited):
		writeJSON(w, http.StatusTooManyRequests, privacyErrorResponse{Error: "rate_limited"})
	case errors.Is(err, privacy.ErrInvalidToken),
		errors.Is(err, privacy.ErrUnsupportedFactor),
		errors.Is(err, privacy.ErrUserNotFound):
		writeJSON(w, http.StatusUnauthorized, privacyErrorResponse{Error: "invalid_token"})
	default:
		s.logger.Error("privacy: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, privacyErrorResponse{Error: "server_error"})
	}
}
