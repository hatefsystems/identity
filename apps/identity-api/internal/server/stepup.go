package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

type stepUpErrorResponse struct {
	Error string `json:"error"`
}

// stepUpChallengeResponse advertises which factors the caller's own account can
// present, plus the WebAuthn assertion options when a passkey ceremony started.
//
// There is no account-enumeration concern here: the caller already holds a valid
// session for this account, so listing their own factors reveals nothing they do
// not already know, and withholding it would leave the portal unable to explain
// why a sensitive action cannot proceed (docs/frontend-pages.md §5.3).
type stepUpChallengeResponse struct {
	Methods  []string                      `json:"methods"`
	WebAuthn *protocol.CredentialAssertion `json:"webauthn,omitempty"`
}

// stepUpVerifyRequest is the body of the verify request. Method selects the
// factor; exactly one of Assertion or Code is meaningful for a given method.
type stepUpVerifyRequest struct {
	Method    string          `json:"method"`
	Assertion json.RawMessage `json:"assertion"`
	Code      string          `json:"code"`
}

// stepUpVerifyResponse carries the minted grant. token_type is "StepUp" rather
// than "Bearer" because the grant is not a bearer credential for an API: it
// authorises a single operation on top of an existing session, and is presented
// in X-Step-Up-Auth rather than Authorization.
type stepUpVerifyResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	ACR       string `json:"acr"`
}

// registerStepUpRoutes mounts the step-up challenge and verify endpoints from
// docs/api-design.md §1.3. Both require a live session: step-up raises the
// authentication context of an existing session, so there is nothing to raise
// without one.
//
// It is only called when a step-up service is configured (Deps.StepUp != nil).
func (s *Server) registerStepUpRoutes() {
	guard, ok := s.sessionGuard("stepup")
	if !ok {
		return
	}

	s.router.Route("/api/v1/auth/stepup", func(r chi.Router) {
		r.Use(guard.Handler)

		r.Post("/challenge", s.handleStepUpChallenge())
		r.Post("/verify", s.handleStepUpVerify())
	})
}

// handleStepUpChallenge serves POST /api/v1/auth/stepup/challenge. It reports the
// available factors and, when the account holds a passkey, starts a
// user-verification-required assertion ceremony.
func (s *Server) handleStepUpChallenge() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		current, ok := session.FromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusInternalServerError, stepUpErrorResponse{Error: "server_error"})
			return
		}

		result, err := s.deps.StepUp.Challenge(r.Context(), userID, current.ID)
		if err != nil {
			s.writeStepUpError(w, "step-up challenge", err)
			return
		}

		writeJSON(w, http.StatusOK, stepUpChallengeResponse{
			Methods:  result.Methods,
			WebAuthn: result.WebAuthn,
		})
	}
}

// handleStepUpVerify serves POST /api/v1/auth/stepup/verify. On a verified factor
// it returns a short-lived, single-use grant bound to the caller's session.
func (s *Server) handleStepUpVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}
		current, ok := session.FromContext(r.Context())
		if !ok {
			// Unreachable behind RequireSession; webauthnSessionUser above would
			// already have failed.
			s.logger.Error("stepup: verify handler reached without a session in context")
			writeJSON(w, http.StatusInternalServerError, stepUpErrorResponse{Error: "server_error"})
			return
		}

		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req stepUpVerifyRequest
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, stepUpErrorResponse{Error: "invalid_request"})
				return
			}
		}

		// The trusted-proxy middleware records a canonical bare client IP in the
		// request context; untrusted forwarding headers never reach this limit.
		token, _, err := s.deps.StepUp.Verify(r.Context(), stepup.VerifyParams{
			UserID:    userID,
			SessionID: current.ID,
			Method:    req.Method,
			Assertion: req.Assertion,
			Code:      req.Code,
			ClientIP:  clientip.FromRequest(r),
			DPoPJKT:   current.DPoPJKT,
		})
		if err != nil {
			s.record(r, audit.Event{
				EventType:    audit.EventStepUpDenied,
				ActionStatus: audit.StatusFailure,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload: map[string]any{
					"method":    stepUpAuditMethod(req.Method),
					"reason":    stepUpFailureReason(err),
					"ip_subnet": ratelimit.Subnet(clientip.FromRequest(r)),
				},
			})
			s.writeStepUpError(w, "step-up verify", err)
			return
		}

		// Ledgered (Class B): a grant unlocks MFA teardown, phone removal, and
		// recovery-code regeneration, so it is the pivot an account-takeover
		// investigation starts from.
		s.record(r, audit.Event{
			EventType:    audit.EventStepUpGranted,
			ActionStatus: audit.StatusSuccess,
			ActorID:      userID,
			SubjectID:    &userID,
			Payload:      map[string]any{"method": stepUpAuditMethod(req.Method)},
			Security:     &audit.SecurityContext{AccountRef: userID},
		})

		// The grant is a short-lived credential: keep it out of any intermediary
		// or browser cache, matching the recovery-code batch response.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, stepUpVerifyResponse{
			Token:     token,
			TokenType: "StepUp",
			// Reported from the configured policy rather than by subtracting a
			// second clock reading from expiresAt, so the value a client sees is
			// exactly the lifetime the service promises.
			ExpiresIn: int(s.deps.StepUp.TokenTTL().Seconds()),
			ACR:       stepup.ACRStepUp,
		})
	}
}

// writeStepUpError maps step-up domain errors to HTTP responses.
//
// Every credential failure collapses into an opaque 401 so nothing distinguishes
// a stale challenge, a wrong passcode, a replayed passcode, or a failed
// signature — matching writeWebAuthnLoginError. The two exceptions are both
// user-actionable and leak nothing, because the caller is already authenticated
// as this account:
//
//   - a missing user-verification flag (403) tells the user their authenticator
//     performed only a presence test, so they should use a PIN/biometric-capable
//     device or fall back to TOTP;
//   - no enrolled factor at all (409) tells the portal to explain that a passkey
//     or TOTP must be enrolled before sensitive operations become reachable.
func (s *Server) writeStepUpError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, stepup.ErrUserNotFound),
		errors.Is(err, stepup.ErrAccountNotActive):
		writeJSON(w, http.StatusUnauthorized, stepUpErrorResponse{Error: "unauthorized"})
	case errors.Is(err, stepup.ErrNoFactorAvailable):
		writeJSON(w, http.StatusConflict, stepUpErrorResponse{Error: "no_stepup_factor"})
	case errors.Is(err, stepup.ErrUserVerificationRequired):
		writeJSON(w, http.StatusForbidden, stepUpErrorResponse{Error: "user_verification_required"})
	case errors.Is(err, stepup.ErrUnsupportedMethod),
		errors.Is(err, stepup.ErrMethodUnavailable):
		writeJSON(w, http.StatusBadRequest, stepUpErrorResponse{Error: "unsupported_method"})
	case errors.Is(err, stepup.ErrRateLimited):
		writeJSON(w, http.StatusTooManyRequests, stepUpErrorResponse{Error: "rate_limited"})
	case errors.Is(err, stepup.ErrInvalidCredentials),
		errors.Is(err, stepup.ErrCodeReplayed):
		writeJSON(w, http.StatusUnauthorized, stepUpErrorResponse{Error: "invalid_credentials"})
	default:
		s.logger.Error("stepup: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, stepUpErrorResponse{Error: "server_error"})
	}
}

// stepUpAuditMethod clamps the client-supplied method to the values the service
// actually implements.
//
// req.Method is arbitrary request data. Copying it verbatim would let any
// authenticated caller choose the contents of an audit payload — and, on the
// granted path, of an append-only Class B ledger row. Length is already capped by
// readWebAuthnBody, but a bounded vocabulary is what makes the field aggregatable
// and keeps injected text out of DPO exports.
func stepUpAuditMethod(method string) string {
	switch method {
	case stepup.MethodWebAuthn:
		return stepup.MethodWebAuthn
	case stepup.MethodTOTP:
		return stepup.MethodTOTP
	case "":
		// The service treats an absent method as "pick the strongest available",
		// so this is a legitimate request shape, not a malformed one.
		return "unspecified"
	default:
		return "unsupported"
	}
}

// stepUpFailureReason maps a step-up failure to a stable audit label.
//
// Unlike writeStepUpError, which deliberately collapses every credential failure
// into one opaque 401 so a caller learns nothing, the audit trail keeps them
// distinct: the whole point of recording a denial is that an investigator can tell
// a replayed passcode from a bad signature from a stale challenge. The response
// stays opaque; only the internal record is precise.
func stepUpFailureReason(err error) string {
	switch {
	case errors.Is(err, stepup.ErrInvalidCredentials):
		return "invalid_credentials"
	case errors.Is(err, stepup.ErrCodeReplayed):
		return "code_replayed"
	case errors.Is(err, stepup.ErrUserVerificationRequired):
		return "user_verification_required"
	case errors.Is(err, stepup.ErrNoFactorAvailable):
		return "no_factor_available"
	case errors.Is(err, stepup.ErrUnsupportedMethod):
		return "unsupported_method"
	case errors.Is(err, stepup.ErrMethodUnavailable):
		return "method_unavailable"
	case errors.Is(err, stepup.ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, stepup.ErrUserNotFound), errors.Is(err, stepup.ErrAccountNotActive):
		return "unauthorized"
	default:
		return "internal_error"
	}
}
