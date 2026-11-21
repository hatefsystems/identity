package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const accountDeletionProofPath = "/api/v1/auth/action-proofs/account-deletion"

// AccountDeletionProofs earns deletion-only authority for the request's live
// browser session. Consumption belongs to the eventual deletion transaction.
type AccountDeletionProofs interface {
	Challenge(ctx context.Context, sess session.Session, password, channel, sourceIP string) (string, time.Time, error)
	Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error)
}

func (s *Server) registerActionProofRoutes() {
	guard, ok := s.sessionGuard("account deletion proofs")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Post(accountDeletionProofPath+"/challenge", s.handleActionProof(false))
	s.router.With(guard.Handler).Post(accountDeletionProofPath+"/verify", s.handleActionProof(true))
}

func readActionProofRequest(r *http.Request, verify bool) (map[string]string, bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Body == nil {
		return nil, false
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, false
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || len(params) > 1 ||
		len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(body) > 8192 || !utf8.Valid(body) || !json.Valid(body) || !uniqueJSONFields(body) {
		return nil, false
	}
	names := []string{"password", "channel"}
	if verify {
		names = []string{"challenge", "code"}
	}
	fields, ok := exactObject(body, names, nil)
	if !ok {
		return nil, false
	}
	values := make(map[string]string, 2)
	for _, name := range names {
		raw := fields[name]
		if len(raw) < 2 || raw[0] != '"' || !validNameJSONString(raw) {
			return nil, false
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return nil, false
		}
		values[name] = value
	}
	if !verify && values["channel"] != contactcode.ChannelEmail && values["channel"] != contactcode.ChannelSMS {
		return nil, false
	}
	return values, true
}

func (s *Server) handleActionProof(verify bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := profileSession(w, r)
		if !ok {
			return
		}
		values, ok := readActionProofRequest(r, verify)
		if !ok {
			writeJSON(w, http.StatusBadRequest, sessionErrorResponse{Error: "invalid_request"})
			return
		}
		if s.deps.AccountDeletionProofs == nil {
			writeActionProofError(w, actionproof.ErrUnavailable)
			return
		}
		var handle string
		var deadline time.Time
		var err error
		if verify {
			handle, deadline, err = s.deps.AccountDeletionProofs.Verify(r.Context(), sess, values["challenge"], values["code"])
		} else {
			handle, deadline, err = s.deps.AccountDeletionProofs.Challenge(r.Context(), sess, values["password"], values["channel"], clientip.FromRequest(r))
		}
		// An uncertain service outcome cannot expose even a tentative handle.
		if err != nil {
			writeActionProofError(w, err)
			return
		}
		if handle == "" || deadline.IsZero() {
			writeActionProofError(w, actionproof.ErrUnavailable)
			return
		}
		if verify {
			writeJSON(w, http.StatusOK, struct {
				Proof     string    `json:"action_proof"`
				ExpiresAt time.Time `json:"expires_at"`
			}{handle, deadline})
			return
		}
		writeJSON(w, http.StatusAccepted, struct {
			Challenge string    `json:"challenge"`
			ExpiresAt time.Time `json:"expires_at"`
		}{handle, deadline})
	}
}

func writeActionProofError(w http.ResponseWriter, err error) {
	status, key := http.StatusServiceUnavailable, "temporarily_unavailable"
	switch {
	case errors.Is(err, actionproof.ErrOutcomeUnknown), errors.Is(err, contactcode.ErrOutcomeUnknown):
		key = "outcome_unknown"
	case errors.Is(err, actionproof.ErrRateLimited), errors.Is(err, contactcode.ErrRateLimited), errors.Is(err, contactcode.ErrLockedOut):
		status, key = http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, actionproof.ErrUnauthorized):
		status, key = http.StatusForbidden, "insufficient_user_authentication"
	case errors.Is(err, actionproof.ErrInvalid), errors.Is(err, contactcode.ErrInvalid):
		status, key = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, contactcode.ErrInvalidCode), errors.Is(err, contactcode.ErrNoActiveCode):
		status, key = http.StatusUnauthorized, "invalid_code"
	}
	writeJSON(w, status, sessionErrorResponse{Error: key})
}
