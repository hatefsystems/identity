package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// UsernameReader reads ownership after checking the account's current auth version.
type UsernameReader interface {
	Get(context.Context, uuid.UUID, int64) (*username.ReadResult, error)
}

func (s *Server) registerUsernameRoutes() {
	guard, ok := s.sessionGuard("username")
	if !ok {
		return
	}
	// Initial claims remain deliberately unmounted until username-bound fresh
	// proof is separately implemented. Generic step-up grants do not authorize it.
	s.router.With(guard.Handler).Get("/api/v1/users/me/username", s.handleUsernameGet())
}

func (s *Server) handleUsernameGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, id, ok := profileSession(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		value, err := s.deps.Usernames.Get(r.Context(), id, sess.AuthVersion)
		if err != nil {
			status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
			if errors.Is(err, username.ErrUnauthorized) {
				status, code = http.StatusUnauthorized, "session_required"
				w.Header().Set("WWW-Authenticate", "Cookie")
			}
			writeJSON(w, status, map[string]string{"error": code})
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Username *username.ReadResult `json:"username"`
		}{Username: value})
	}
}
