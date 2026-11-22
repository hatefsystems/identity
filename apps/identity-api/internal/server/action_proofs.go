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

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const accountDeletionProofPath = "/api/v1/auth/action-proofs/account-deletion"
const passwordChangeProofPath = "/api/v1/auth/action-proofs/password-change" //nolint:gosec // G101: fixed public API route, not a credential.
const firstPasskeyProofPath = "/api/v1/auth/action-proofs/first-passkey"     //nolint:gosec // G101: fixed public API route, not a credential.

// AccountDeletionProofs earns deletion-only authority for the request's live
// browser session. Consumption belongs to the eventual deletion transaction.
type AccountDeletionProofs interface {
	Challenge(ctx context.Context, sess session.Session, password, channel, sourceIP string) (string, time.Time, error)
	Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error)
}

// FirstPasskeyProofs issues only first-start authority; the WebAuthn service owns
// the caller transactions and commits. Final validation is read-only.
type FirstPasskeyProofs interface {
	ChallengeFirstPasskey(context.Context, session.Session, string, string, string) (string, time.Time, error)
	VerifyFirstPasskey(context.Context, session.Session, string, string) (string, time.Time, error)
	CheckFirstPasskey(context.Context, session.Session, string) error
	ConsumeFirstPasskeyStartTx(context.Context, pgx.Tx, session.Session, string) (actionproof.FirstPasskeyAuthorization, error)
	ValidateFirstPasskeyTx(context.Context, pgx.Tx, session.Session, actionproof.FirstPasskeyAuthorization) error
}

func (s *Server) registerFirstPasskeyProofRoutes() {
	guard, ok := s.sessionGuard("first passkey proofs")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Post(firstPasskeyProofPath+"/challenge", s.handleFixedProofCeremony(false, contactcode.PurposeFirstPasskey))
	s.router.With(guard.Handler).Post(firstPasskeyProofPath+"/verify", s.handleFixedProofCeremony(true, contactcode.PurposeFirstPasskey))
}

func (s *Server) registerActionProofRoutes() {
	guard, ok := s.sessionGuard("account deletion proofs")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Post(accountDeletionProofPath+"/challenge", s.handleActionProof(false))
	s.router.With(guard.Handler).Post(accountDeletionProofPath+"/verify", s.handleActionProof(true))
}

func (s *Server) registerPasswordChangeProofRoutes() {
	guard, ok := s.sessionGuard("password change proofs")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Post(passwordChangeProofPath+"/challenge", s.handleProofCeremony(false, true))
	s.router.With(guard.Handler).Post(passwordChangeProofPath+"/verify", s.handleProofCeremony(true, true))
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
	return s.handleProofCeremony(verify, false)
}

func (s *Server) handleProofCeremony(verify, passwordChange bool) http.HandlerFunc {
	purpose := contactcode.PurposeAccountDeletion
	if passwordChange {
		purpose = contactcode.PurposePasswordChange
	}
	return s.handleFixedProofCeremony(verify, purpose)
}

func (s *Server) handleFixedProofCeremony(verify bool, purpose string) http.HandlerFunc {
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
		service := s.deps.AccountDeletionProofs
		if purpose == contactcode.PurposePasswordChange {
			service = s.deps.PasswordChangeProofs
		}
		if purpose != contactcode.PurposeFirstPasskey && service == nil || purpose == contactcode.PurposeFirstPasskey && s.deps.FirstPasskeyProofs == nil {
			writeActionProofError(w, actionproof.ErrUnavailable)
			return
		}
		var handle string
		var deadline time.Time
		var err error
		if purpose == contactcode.PurposeFirstPasskey {
			if verify {
				handle, deadline, err = s.deps.FirstPasskeyProofs.VerifyFirstPasskey(r.Context(), sess, values["challenge"], values["code"])
			} else {
				handle, deadline, err = s.deps.FirstPasskeyProofs.ChallengeFirstPasskey(r.Context(), sess, values["password"], values["channel"], clientip.FromRequest(r))
			}
		} else if verify {
			handle, deadline, err = service.Verify(r.Context(), sess, values["challenge"], values["code"])
		} else {
			handle, deadline, err = service.Challenge(r.Context(), sess, values["password"], values["channel"], clientip.FromRequest(r))
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
		session.OutcomeCommitted(r.Context())
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
