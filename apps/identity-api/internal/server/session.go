package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// sessionResponse is the public, non-secret projection of a session returned by
// the self-service listing (GET /api/v1/users/me/sessions). It deliberately
// omits the session token and its storage hash: only the stable public ID
// (usable for targeted revocation) plus audit metadata are exposed.
type sessionResponse struct {
	// ID is the stable public identifier used to revoke this session.
	ID string `json:"id"`
	// IP is the client source address captured at session creation.
	IP string `json:"ip,omitempty"`
	// UserAgent identifies the client device/browser.
	UserAgent string `json:"user_agent,omitempty"`
	// Current flags the session the requesting cookie belongs to, so the SPA
	// can label "this device" and steer the user away from revoking it.
	Current bool `json:"current"`
	// CreatedAt is when the session was issued (RFC 3339).
	CreatedAt time.Time `json:"created_at"`
	// LastSeenAt is when the session was last used (RFC 3339).
	LastSeenAt time.Time `json:"last_seen_at"`
}

// sessionErrorResponse is the minimal JSON error envelope for the first-party
// account session routes. These are not OAuth endpoints, so they use a simple
// {"error": "..."} body rather than the RFC 6749 token error shape.
type sessionErrorResponse struct {
	Error string `json:"error"`
}

// registerSessionRoutes mounts the browser session lifecycle endpoints. It is
// only called when a session manager is configured (Deps.SessionManager !=
// nil). Logout is unauthenticated by design — it is idempotent and only ever
// clears the caller's own cookie — while the self-service list/revoke routes
// are gated behind RequireSession so a request must present a live session for
// the user it acts on.
func (s *Server) registerSessionRoutes() {
	s.router.Post("/api/v1/auth/logout", s.handleLogout())

	// RequireSession is constructed once; the manager is guaranteed non-nil by
	// the caller, so NewRequireSession cannot fail here.
	guard, err := session.NewRequireSession(s.deps.SessionManager)
	if err != nil {
		// Unreachable given the non-nil manager, but surface it rather than
		// mounting unguarded routes.
		s.logger.Error("session: failed to build RequireSession middleware", "error", err.Error())
		return
	}

	s.router.Route("/api/v1/users/me/sessions", func(r chi.Router) {
		r.Use(guard.Handler)
		r.Get("/", s.handleListSessions())
		r.Delete("/{id}", s.handleRevokeSession())
	})
}

// handleLogout serves POST /api/v1/auth/logout. It revokes the session bound to
// the request cookie and clears that cookie. Revocation is idempotent: a
// request with no cookie (or an already-revoked session) still returns 204, so
// logout is safe to retry and never leaks whether a session existed.
func (s *Server) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		revoked, ok, err := s.deps.SessionManager.Revoke(w, r)
		if err != nil {
			s.logger.Error("session: logout failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, sessionErrorResponse{
				Error: "logout_failed",
			})
			return
		}

		// Audited only when a live session was actually revoked. This route is
		// unauthenticated, so recording every call would let any client append
		// rows to the audit chain with no account to attribute them to —
		// mvp_audit_logs.actor_id is NOT NULL, and uuid.Nil would be a fabrication.
		// A no-cookie or already-expired logout is a no-op and stays out of the log.
		if ok {
			if userID, parseErr := uuid.Parse(revoked.UserID); parseErr == nil {
				s.record(r, audit.Event{
					EventType:    audit.EventSessionLoggedOut,
					ActionStatus: audit.StatusSuccess,
					ActorID:      userID,
					SubjectID:    &userID,
					// The session's public ID, never its token or storage hash.
					Payload: map[string]any{"session_id": revoked.ID},
				})
			} else {
				// The store held a session whose user id is not a UUID. That is a
				// data-integrity fault, not a client error: the logout itself
				// succeeded, so it must not fail, but it cannot be attributed.
				s.logger.Error("session: revoked session carries a non-UUID user id",
					"error", parseErr.Error())
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleListSessions serves GET /api/v1/users/me/sessions. It returns every
// live session for the authenticated user, newest-first, flagging the one the
// request itself is authenticated with so the client can label the current
// device.
func (s *Server) handleListSessions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		current, ok := session.FromContext(r.Context())
		if !ok {
			// RequireSession guarantees a session in context; treat its absence
			// as an internal inconsistency rather than an auth failure.
			s.logger.Error("session: list handler reached without a session in context")
			writeJSON(w, http.StatusInternalServerError, sessionErrorResponse{Error: "server_error"})
			return
		}

		sessions, err := s.deps.SessionManager.List(current.UserID)
		if err != nil {
			s.logger.Error("session: list failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, sessionErrorResponse{Error: "server_error"})
			return
		}

		out := make([]sessionResponse, 0, len(sessions))
		for _, sess := range sessions {
			out = append(out, sessionResponse{
				ID:         sess.ID,
				IP:         sess.IP,
				UserAgent:  sess.UserAgent,
				Current:    sess.ID == current.ID,
				CreatedAt:  sess.CreatedAt,
				LastSeenAt: sess.LastSeenAt,
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleRevokeSession serves DELETE /api/v1/users/me/sessions/{id}. It revokes a
// single session by its public ID, scoped to the authenticated user so a caller
// can only revoke their own sessions. It returns 204 on success and 404 when no
// matching session exists for the user (an unknown, already-revoked, or
// foreign-owned ID are indistinguishable to the caller).
func (s *Server) handleRevokeSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		current, ok := session.FromContext(r.Context())
		if !ok {
			s.logger.Error("session: revoke handler reached without a session in context")
			writeJSON(w, http.StatusInternalServerError, sessionErrorResponse{Error: "server_error"})
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeJSON(w, http.StatusNotFound, sessionErrorResponse{Error: "not_found"})
			return
		}

		revoked, err := s.deps.SessionManager.RevokeByID(current.UserID, id)
		if err != nil {
			s.logger.Error("session: revoke by id failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, sessionErrorResponse{Error: "server_error"})
			return
		}
		if !revoked {
			writeJSON(w, http.StatusNotFound, sessionErrorResponse{Error: "not_found"})
			return
		}

		// RevokeByID already scopes to the caller's own account and reports whether
		// a session was really removed, so no state-change guard is needed here: an
		// unknown, already-revoked, or foreign-owned ID took the 404 path above.
		if userID, parseErr := uuid.Parse(current.UserID); parseErr == nil {
			s.record(r, audit.Event{
				EventType:    audit.EventSessionRevoked,
				ActionStatus: audit.StatusSuccess,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload: map[string]any{
					"session_id": id,
					// Distinguishes killing another device from ending this one,
					// which matters when reconstructing a takeover response.
					"self": id == current.ID,
				},
			})
		} else {
			s.logger.Error("session: revoke handler session carries a non-UUID user id",
				"error", parseErr.Error())
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
