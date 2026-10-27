package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const profileUpdatedEvent = "profile.updated"

type profileResponse struct {
	ID                uuid.UUID              `json:"id"`
	Email             string                 `json:"email"`
	DisplayName       string                 `json:"display_name"`
	Status            string                 `json:"status"`
	LifecycleRevision string                 `json:"lifecycle_revision"`
	DeletionEnabled   bool                   `json:"deletion_enabled"`
	Session           profileSessionResponse `json:"session"`
}

type profileSessionResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) registerProfileRoutes() {
	guard, ok := s.sessionGuard("profile")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Get("/api/v1/users/me", s.handleProfileGet())
	s.router.With(guard.Handler).Patch("/api/v1/users/me", s.handleProfileUpdate())
}

func profileSession(w http.ResponseWriter, r *http.Request) (session.Session, uuid.UUID, bool) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	sess, ok := session.FromContext(r.Context())
	id, err := uuid.Parse(sess.UserID)
	proof := dpop.ProofFromContext(r.Context())
	if !ok || err != nil || id == uuid.Nil || sess.UserID != id.String() || sess.ID == "" ||
		sess.Kind != session.KindAuthenticated || !sess.AuthVersionSet || sess.AuthVersion < 0 ||
		sess.DPoPJKT == "" || proof == nil || proof.JKT != sess.DPoPJKT ||
		!time.Now().Before(sess.AbsoluteExpiry) || !time.Now().Before(sess.IdleExpiry) {
		w.Header().Set("WWW-Authenticate", "Cookie")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session_required"})
		return session.Session{}, uuid.Nil, false
	}
	return sess, id, true
}

func (s *Server) writeProfile(w http.ResponseWriter, p profile.Profile, sess session.Session) {
	writeJSON(w, http.StatusOK, profileResponse{
		ID: p.ID, Email: p.Email, DisplayName: p.DisplayName, Status: p.Status,
		LifecycleRevision: p.LifecycleRevision,
		DeletionEnabled: s.deps.PrivacyDeletionEnabled && s.deps.Privacy != nil &&
			s.deps.StepUp != nil && s.deps.SessionManager != nil && s.deps.DPoPValidator != nil,
		Session: profileSessionResponse{ID: sess.ID, ExpiresAt: sess.AbsoluteExpiry.UTC()},
	})
}

func (s *Server) handleProfileGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, id, ok := profileSession(w, r)
		if !ok {
			return
		}
		p, err := s.deps.Profile.Get(r.Context(), id, sess.AuthVersion)
		if err != nil {
			writeProfileError(w, err)
			return
		}
		s.writeProfile(w, p, sess)
	}
}

func (s *Server) handleProfileUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, id, ok := profileSession(w, r)
		if !ok {
			return
		}
		name, revision, err := decodeProfileUpdate(w, r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		result, err := s.deps.Profile.Update(r.Context(), id, sess.AuthVersion, name, revision)
		if err != nil {
			writeProfileError(w, err)
			return
		}
		if result.Changed {
			// Best-effort observation only. The lifecycle intent is already durable;
			// names and old/new values never enter this audit-only event.
			s.record(r, audit.Event{
				EventType: profileUpdatedEvent, ActionStatus: audit.StatusSuccess,
				ActorID: id, SubjectID: &id,
				Payload: map[string]any{"changed_fields": []string{"display_name"}, "lifecycle_revision": result.Profile.LifecycleRevision},
			})
		}
		s.writeProfile(w, result.Profile, sess)
	}
}

func writeProfileError(w http.ResponseWriter, err error) {
	code, reason := http.StatusServiceUnavailable, "temporarily_unavailable"
	switch {
	case errors.Is(err, profile.ErrUnauthorized):
		code, reason = http.StatusUnauthorized, "session_required"
		w.Header().Set("WWW-Authenticate", "Cookie")
	case errors.Is(err, profile.ErrConflict):
		code, reason = http.StatusConflict, "profile_conflict"
	case errors.Is(err, profile.ErrInvalidName), errors.Is(err, profile.ErrInvalidRevision):
		code, reason = http.StatusBadRequest, "invalid_request"
	}
	writeJSON(w, code, map[string]string{"error": reason})
}

func decodeProfileUpdate(w http.ResponseWriter, r *http.Request) (string, string, error) {
	invalid := errors.New("profile: invalid request")
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(r.Header.Values("Content-Type")) != 1 ||
		len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return "", "", invalid
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil || !utf8.Valid(raw) {
		return "", "", invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", "", invalid
	}
	values := make(map[string]string, 2)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "display_name" && key != "expected_revision") {
			return "", "", invalid
		}
		if _, exists := values[key]; exists {
			return "", "", invalid
		}
		var encoded json.RawMessage
		if decoder.Decode(&encoded) != nil || len(encoded) < 2 || encoded[0] != '"' || !validNameJSONString(encoded) {
			return "", "", invalid
		}
		var value string
		if json.Unmarshal(encoded, &value) != nil {
			return "", "", invalid
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(values) != 2 {
		return "", "", invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", "", invalid
	}
	return values["display_name"], values["expected_revision"], nil
}

// encoding/json replaces lone UTF-16 surrogates with U+FFFD. Reject them rather
// than silently changing an invalid name; genuine U+FFFD and paired escapes work.
// The caller must first validate that raw is a well-formed JSON string.
func validNameJSONString(raw []byte) bool {
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if !utf16.IsSurrogate(rune(value)) {
			continue
		}
		if value > 0xDBFF || i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		i += 6
	}
	return true
}
