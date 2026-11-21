package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/passwordmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

const passwordPath = "/api/v1/users/me/password" //nolint:gosec // G101: fixed public API route, not a credential.

func (s *Server) registerPasswordRoutes() {
	guard, ok := s.sessionGuard("password management")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Put(passwordPath, s.handlePasswordMutation())
	s.router.With(guard.Handler).Delete(passwordPath, s.handlePasswordMutation())
}

func readPasswordRequest(r *http.Request) (string, string, bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", "", false
	}
	if r.Method == http.MethodDelete {
		if r.Body != nil && r.Body != http.NoBody {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 {
				return "", "", false
			}
		}
		return "remove", "", true
	}
	if r.Body == nil || r.Body == http.NoBody {
		return "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(body) > 8192 || !utf8.Valid(body) || !json.Valid(body) || !uniqueJSONFields(body) {
		return "", "", false
	}
	fields, ok := exactObject(body, []string{"operation", "new_password"}, nil)
	if !ok {
		return "", "", false
	}
	values := make(map[string]string, 2)
	for _, name := range []string{"operation", "new_password"} {
		raw := fields[name]
		if len(raw) < 2 || raw[0] != '"' || !validNameJSONString(raw) {
			return "", "", false
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", "", false
		}
		values[name] = value
	}
	if values["operation"] != "add" && values["operation"] != "change" {
		return "", "", false
	}
	return values["operation"], values["new_password"], true
}

func (s *Server) handlePasswordMutation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := profileSession(w, r)
		if !ok {
			return
		}
		operation, secret, ok := readPasswordRequest(r)
		if !ok {
			writePasswordError(w, passwordmanager.ErrInvalid)
			return
		}
		grants, proofs := r.Header.Values(stepup.HeaderStepUpAuth), r.Header.Values("X-Action-Proof")
		if len(grants)+len(proofs) != 1 || len(proofs) == 1 && operation != "change" {
			writePasswordError(w, passwordmanager.ErrUnauthorized)
			return
		}
		auth := passwordmanager.Authorization{}
		if len(grants) == 1 {
			if s.deps.StepUp == nil || grants[0] == "" || strings.Contains(grants[0], ",") || len(grants[0]) > 16*1024 {
				writePasswordError(w, passwordmanager.ErrUnauthorized)
				return
			}
			grant, err := s.deps.StepUp.Validate(r.Context(), grants[0], sess)
			if err != nil {
				writePasswordError(w, err)
				return
			}
			auth.Grant = grant
		} else {
			if proofs[0] == "" || strings.Contains(proofs[0], ",") || len(proofs[0]) > 128 {
				writePasswordError(w, passwordmanager.ErrUnauthorized)
				return
			}
			auth.Proof = proofs[0]
		}
		changed, err := s.deps.Passwords.Mutate(r.Context(), sess, operation, secret, auth, clientip.FromRequest(r))
		if err != nil {
			writePasswordError(w, err)
			return
		}
		if changed {
			session.SecurityChangeCommitted(r.Context())
		} else {
			session.OutcomeCommitted(r.Context())
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func writePasswordError(w http.ResponseWriter, err error) {
	status, key := http.StatusServiceUnavailable, "temporarily_unavailable"
	switch {
	case errors.Is(err, passwordmanager.ErrOutcomeUnknown), errors.Is(err, actionproof.ErrOutcomeUnknown):
		key = "outcome_unknown"
	case errors.Is(err, passwordmanager.ErrInvalid), errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrInvalidUTF8), errors.Is(err, password.ErrCompromisedPassword):
		status, key = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, passwordmanager.ErrUnauthorized), errors.Is(err, actionproof.ErrInvalid), errors.Is(err, actionproof.ErrUnauthorized), errors.Is(err, stepup.ErrNoGrant), errors.Is(err, stepup.ErrInvalidGrant), errors.Is(err, stepup.ErrGrantConsumed), errors.Is(err, stepup.ErrGrantNotForSession):
		status, key = http.StatusForbidden, "insufficient_user_authentication"
	case errors.Is(err, passwordmanager.ErrConflict):
		status, key = http.StatusConflict, "password_state_conflict"
	case errors.Is(err, accountpolicy.ErrLastCredential):
		status, key = http.StatusConflict, "last_credential"
	case errors.Is(err, accountpolicy.ErrLastFactor):
		status, key = http.StatusConflict, "last_factor"
	case errors.Is(err, passwordmanager.ErrRateLimited), errors.Is(err, actionproof.ErrRateLimited):
		status, key = http.StatusTooManyRequests, "rate_limited"
	}
	writeJSON(w, status, sessionErrorResponse{Error: key})
}
