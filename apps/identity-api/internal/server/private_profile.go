package server

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// PrivateProfileReader is separate from the routine public-profile bootstrap.
type PrivateProfileReader interface {
	Get(context.Context, session.Session) (profile.PrivateSnapshot, error)
	Update(context.Context, session.Session, profile.PrivateUpdate) (profile.PrivateUpdateResult, error)
}

func (s *Server) registerPrivateProfileRoutes() {
	guard, ok := s.sessionGuard("private profile")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Get("/api/v1/users/me/private-data", s.handlePrivateProfileGet())
	s.router.With(guard.Handler).Patch("/api/v1/users/me/private-data", s.handlePrivateProfileUpdate())
}

func (s *Server) handlePrivateProfileGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := profileSession(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		result, err := s.deps.PrivateProfile.Get(r.Context(), sess)
		if err != nil {
			writePrivateProfileError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (s *Server) handlePrivateProfileUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, id, ok := profileSession(w, r)
		if !ok {
			return
		}
		in, err := decodePrivateProfileUpdate(w, r)
		if err != nil {
			writePrivateProfileError(w, err)
			return
		}
		result, err := s.deps.PrivateProfile.Update(r.Context(), sess, in)
		if err != nil {
			writePrivateProfileError(w, err)
			return
		}
		if result.Changed {
			s.record(r, audit.Event{EventType: profileUpdatedEvent, ActionStatus: audit.StatusSuccess, ActorID: id, SubjectID: &id,
				Payload: map[string]any{"changed_fields": []string{"private_profile"}, "lifecycle_revision": result.Snapshot.LifecycleRevision}})
		}
		writeJSON(w, http.StatusOK, result.Snapshot)
	}
}

func decodePrivateProfileUpdate(w http.ResponseWriter, r *http.Request) (profile.PrivateUpdate, error) {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return profile.PrivateUpdate{}, profile.ErrInvalidPrivateData
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		return profile.PrivateUpdate{}, profile.ErrInvalidPrivateData
	}
	defer clear(raw)
	return profile.DecodePrivateUpdate(raw)
}

func writePrivateProfileError(w http.ResponseWriter, err error) {
	if errors.Is(err, profile.ErrOutcomeUnknown) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "outcome_unknown"})
		return
	}
	if errors.Is(err, profile.ErrInvalidPrivateData) || errors.Is(err, profile.ErrInvalidPersonalName) || errors.Is(err, profile.ErrInvalidBirthday) || errors.Is(err, profile.ErrInvalidGender) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	writeProfileError(w, err)
}
