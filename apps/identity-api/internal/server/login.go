package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/login"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func (s *Server) registerLoginRoutes() {
	if s.deps.PasswordLoginEnabled {
		for _, operation := range []string{"", "code/request", "code/verify"} {
			path := "/api/v1/auth/login"
			if operation != "" {
				path += "/" + operation
			}
			s.router.With(s.loginChallengeAdmission).Post(path, s.handleLogin(operation))
		}
	}
	// Completion also serves existing passkey sign-in; disabling new methods
	// cannot bypass MFA or current session policy.
	s.router.With(s.loginChallengeAdmission).Post("/api/v1/auth/login/mfa", s.handleLogin("mfa"))
}

func readLoginRequest(r *http.Request, operation string) (map[string]string, bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Body == nil {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(body) > 8192 || !uniqueJSONFields(body) {
		return nil, false
	}
	names := []string{"username", "password"}
	switch operation {
	case "code/request":
		names = []string{"username", "channel"}
	case "code/verify":
		names = []string{"challenge", "code"}
	case "mfa":
		names = []string{"preauthentication", "code"}
	}
	fields, ok := exactObject(body, names, nil)
	if !ok {
		return nil, false
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		raw := fields[name]
		if len(raw) < 2 || raw[0] != '"' || !validNameJSONString(raw) {
			return nil, false
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return nil, false
		}
		values[name] = text
	}
	return values, true
}

func (s *Server) handleLogin(operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		values, ok := readLoginRequest(r, operation)
		if !ok {
			writeJSON(w, http.StatusBadRequest, sessionErrorResponse{Error: "invalid_request"})
			return
		}
		proof, ok := s.verifyBrowserProof(w, r, "")
		if !ok {
			return
		}
		var result login.Result
		var err error
		switch operation {
		case "":
			result, err = s.deps.Login.Password(r.Context(), values["username"], values["password"], proof.JKT, clientip.FromRequest(r))
		case "code/request":
			var handle string
			var deadline time.Time
			handle, deadline, err = s.deps.Login.RequestCode(r.Context(), values["username"], values["channel"], proof.JKT, clientip.FromRequest(r))
			if err == nil {
				writeJSON(w, http.StatusAccepted, struct {
					Status    string    `json:"status"`
					Challenge string    `json:"challenge"`
					ExpiresAt time.Time `json:"expires_at"`
				}{"code_requested", handle, deadline})
				return
			}
		case "code/verify":
			result, err = s.deps.Login.VerifyCode(r.Context(), values["challenge"], proof.JKT, values["code"])
		case "mfa":
			result, err = s.deps.Login.CompleteMFA(r.Context(), values["preauthentication"], proof.JKT, values["code"])
		}
		if err != nil {
			s.writeLoginError(w, err)
			return
		}
		s.finishLogin(w, r, result)
	}
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, result login.Result) {
	if result.Issue == nil {
		if result.Preauthentication == "" || result.ExpiresAt.IsZero() {
			s.writeLoginError(w, login.ErrUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Status            string    `json:"status"`
			Preauthentication string    `json:"preauthentication"`
			ExpiresAt         time.Time `json:"expires_at"`
		}{"mfa_required", result.Preauthentication, result.ExpiresAt})
		return
	}
	if result.Preauthentication != "" {
		s.writeLoginError(w, login.ErrUnavailable)
		return
	}
	p := *result.Issue
	p.IP, p.UserAgent = clientip.FromRequest(r), r.UserAgent()
	if _, err := s.deps.SessionManager.IssueContext(r.Context(), w, p); err != nil {
		if errors.Is(err, session.ErrAccountIneligible) {
			s.writeLoginError(w, login.ErrInvalidCredentials)
		} else {
			s.writeLoginError(w, login.ErrOutcomeUnknown)
		}
		return
	}
	id, err := uuid.Parse(p.UserID)
	if err == nil {
		s.record(r, audit.Event{EventType: audit.EventLoginSucceeded, ActionStatus: audit.StatusSuccess, ActorID: id, SubjectID: &id, Payload: map[string]any{"method": p.Evidence.PrimaryMethod}, Security: &audit.SecurityContext{AccountRef: id}})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeLoginError(w http.ResponseWriter, err error) {
	status, key := http.StatusServiceUnavailable, "temporarily_unavailable"
	switch {
	case errors.Is(err, login.ErrInvalidCredentials):
		status, key = http.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, login.ErrChallengeExpired):
		status, key = http.StatusUnauthorized, "challenge_expired"
	case errors.Is(err, login.ErrRateLimited):
		status, key = http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, login.ErrOutcomeUnknown):
		key = "outcome_unknown"
	}
	writeJSON(w, status, sessionErrorResponse{Error: key})
}
