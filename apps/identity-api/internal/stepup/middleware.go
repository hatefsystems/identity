package stepup

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// RequireStepUp is chi/net-http compatible middleware gating a route on a valid
// step-up grant, per the endpoints marked "Requires Step-up authentication" in
// docs/api-design.md §1.3-1.5.
//
// It must be composed *after* session.RequireSession: the grant is validated
// against the caller's live session (subject and session ID), so a session in the
// request context is a precondition, not something this middleware establishes.
//
// On success the validated Grant is placed in the request context
// (GrantFromContext) and the grant is consumed — it cannot authorise a second
// request.
type RequireStepUp struct {
	svc    *Service
	logger *slog.Logger
}

// NewRequireStepUp constructs step-up enforcement middleware over the given
// Service. A nil logger falls back to slog.Default.
func NewRequireStepUp(svc *Service, logger *slog.Logger) (*RequireStepUp, error) {
	if svc == nil {
		return nil, errors.New("stepup: service is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RequireStepUp{svc: svc, logger: logger}, nil
}

// challengeResponse is the body returned when a gated route is reached without
// sufficient authentication context. It names the required ACR so a client never
// has to hardcode the URI.
type challengeResponse struct {
	Error     string `json:"error"`
	ACRValues string `json:"acr_values"`
}

// Handler wraps next with step-up enforcement.
func (rs *RequireStepUp) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := session.FromContext(r.Context())
		if !ok {
			// RequireSession guarantees a session; reaching here means the
			// middleware chain was assembled wrongly, which is a programming
			// error rather than an authentication failure. Treated the same way
			// server.webauthnSessionUser treats the identical condition.
			rs.logger.Error("stepup: middleware reached without a session in context",
				slog.String("method", r.Method))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		grant, err := rs.svc.Validate(r.Context(), r.Header.Get(HeaderStepUpAuth), sess)
		if err != nil {
			rs.writeChallenge(w, r, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(WithGrant(r.Context(), grant)))
	})
}

// writeChallenge emits the insufficient-authentication challenge.
//
// The status is 403, not 401, because the session itself is valid — what is
// missing is authentication *context*, not authentication. session.RequireSession
// already uses a bare 401 as the signal the SPA reads as "re-authenticate", so
// reusing 401 here would bounce the user through a full login instead of the
// inline step-up overlay described in docs/frontend-pages.md §5.3. The error code
// is borrowed from RFC 9470 (OAuth 2.0 Step Up Authentication Challenge
// Protocol) so the wire vocabulary is standard even though the transport is a
// first-party cookie session rather than a bearer token.
//
// Every validation failure renders identically: a probe cannot tell a missing
// header from an expired, replayed, or foreign grant. Only the server log
// distinguishes them.
func (rs *RequireStepUp) writeChallenge(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNoGrant),
		errors.Is(err, ErrInvalidGrant),
		errors.Is(err, ErrGrantConsumed),
		errors.Is(err, ErrGrantNotForSession):
		// A consumed or mis-bound grant is a security-relevant event: the first
		// is a replay of a spent grant, the second an attempt to pair a grant
		// with a session it was not minted for.
		if errors.Is(err, ErrGrantConsumed) || errors.Is(err, ErrGrantNotForSession) {
			rs.logger.Warn("stepup: grant rejected",
				slog.String("method", r.Method),
				slog.String("reason", err.Error()))
		}
		rs.writeJSON(w, http.StatusForbidden, challengeResponse{
			Error:     "insufficient_user_authentication",
			ACRValues: ACRStepUp,
		})
	default:
		rs.logger.Error("stepup: grant validation failed",
			slog.String("method", r.Method),
			slog.String("error", err.Error()))
		rs.writeJSON(w, http.StatusInternalServerError, challengeResponse{Error: "server_error"})
	}
}

// writeJSON writes a JSON body with the given status. A write failure means the
// client is already gone, so there is nothing useful left to do with the error.
func (rs *RequireStepUp) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
