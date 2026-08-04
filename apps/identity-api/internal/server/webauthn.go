package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// maxWebAuthnBodyBytes caps an authenticator response body. Attestation objects
// carrying a certificate chain are the largest legitimate payload and stay well
// under this, so the limit only serves to bound memory for hostile input.
const maxWebAuthnBodyBytes = 64 << 10

// webauthnErrorResponse is the minimal JSON error envelope for the passkey
// routes, matching the first-party account routes rather than the OAuth error
// shape. The codes are deliberately coarse: the verify endpoints never reveal
// which specific check failed.
type webauthnErrorResponse struct {
	Error string `json:"error"`
}

// webauthnLoginOptionsRequest is the body of the login options request. The
// email names the account whose credentials populate allowCredentials; the
// usernameless (discoverable) variant arrives in Task 4.3.
type webauthnLoginOptionsRequest struct {
	Email string `json:"email"`
}

// webauthnCredentialResponse is the public projection of a registered
// credential. The COSE public key is never exposed; the credential ID is
// base64url-encoded so it round-trips through a URL path for deletion.
type webauthnCredentialResponse struct {
	// ID is the base64url (unpadded) credential ID.
	ID string `json:"id"`
	// AAGUID identifies the authenticator model, or the nil UUID when the
	// authenticator withheld it.
	AAGUID string `json:"aaguid"`
	// AttestationType is the attestation conveyance that was verified at
	// registration (e.g. "none", "packed").
	AttestationType string `json:"attestation_type,omitempty"`
	// UserVerified reports whether the registering ceremony performed user
	// verification (PIN/biometric), i.e. whether this key is a second factor
	// on its own.
	UserVerified bool `json:"user_verified"`
	// BackupEligible reports whether the credential may be synced to a
	// multi-device passkey provider.
	BackupEligible bool `json:"backup_eligible"`
	// BackupState reports whether it is currently backed up.
	BackupState bool `json:"backup_state"`
	// SignCount is the last observed authenticator signature counter.
	SignCount int64 `json:"sign_count"`
	// CreatedAt is when the credential was registered (RFC 3339).
	CreatedAt time.Time `json:"created_at"`
	// LastUsedAt is when it last produced a successful assertion; nil when it
	// has never been used to sign in.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// registerWebAuthnRoutes mounts the passkey ceremony endpoints from
// docs/api-design.md §1.3. It is only called when a WebAuthn service is
// configured (Deps.WebAuthn != nil).
//
// The login endpoints are unauthenticated by definition — they are how a user
// signs in. The registration endpoints and the key listing act on an existing
// account, so they are gated behind RequireSession: a passkey may only be
// enrolled onto the account the caller already holds a live session for, which
// is what stops an attacker from grafting their own authenticator onto someone
// else's account. Step-up verification for key deletion follows in Task 4.7.
func (s *Server) registerWebAuthnRoutes() {
	// The guard is built once, before routing, because the account-scoped
	// routes must not be mounted at all if it cannot be constructed.
	var guard *session.RequireSession
	if s.deps.SessionManager != nil {
		g, err := session.NewRequireSession(s.deps.SessionManager)
		if err != nil {
			// Unreachable given the non-nil manager, but surface it rather than
			// mounting unguarded routes.
			s.logger.Error("webauthn: failed to build RequireSession middleware", "error", err.Error())
			return
		}
		guard = g
	} else {
		// Without a session manager there is no way to authenticate the caller,
		// so the account-scoped routes are left unmounted rather than exposed
		// unguarded.
		s.logger.Warn("webauthn: no session manager configured; registration routes not mounted")
	}

	s.router.Route("/api/v1/auth/webauthn", func(r chi.Router) {
		r.Post("/login/generate-options", s.handleWebAuthnLoginOptions())
		r.Post("/login/verify", s.handleWebAuthnLoginVerify())

		if guard == nil {
			return
		}
		// A nested group scopes RequireSession to the enrolment routes only,
		// leaving the login routes above reachable without a session.
		r.Group(func(pr chi.Router) {
			pr.Use(guard.Handler)
			pr.Post("/register/generate-options", s.handleWebAuthnRegisterOptions())
			pr.Post("/register/verify", s.handleWebAuthnRegisterVerify())
			pr.Get("/keys", s.handleWebAuthnListKeys())
		})
	})
}

// handleWebAuthnRegisterOptions serves POST
// /api/v1/auth/webauthn/register/generate-options. It returns the
// PublicKeyCredentialCreationOptions for the authenticated account, including
// the anonymised 64-bit user handle and the exclusion list of already-registered
// credentials.
func (s *Server) handleWebAuthnRegisterOptions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		options, err := s.deps.WebAuthn.BeginRegistration(r.Context(), userID)
		if err != nil {
			s.writeWebAuthnRegistrationError(w, "begin registration", err)
			return
		}
		writeJSON(w, http.StatusOK, options)
	}
}

// handleWebAuthnRegisterVerify serves POST /api/v1/auth/webauthn/register/verify.
// It verifies the attestation response against the pending challenge (origin, RP
// ID, and attestation are checked inside the service) and persists the new
// credential for the authenticated account.
func (s *Server) handleWebAuthnRegisterVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		row, err := s.deps.WebAuthn.FinishRegistration(r.Context(), userID, body)
		if err != nil {
			s.writeWebAuthnRegistrationError(w, "finish registration", err)
			return
		}
		writeJSON(w, http.StatusCreated, toWebAuthnCredentialResponse(row))
	}
}

// handleWebAuthnListKeys serves GET /api/v1/auth/webauthn/keys, returning the
// authenticated account's registered credentials so the user can audit and
// manage their enrolled authenticators.
func (s *Server) handleWebAuthnListKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		rows, err := s.deps.WebAuthn.ListCredentials(r.Context(), userID)
		if err != nil {
			s.logger.Error("webauthn: list credentials failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
			return
		}

		out := make([]webauthnCredentialResponse, 0, len(rows))
		for _, row := range rows {
			out = append(out, toWebAuthnCredentialResponse(row))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleWebAuthnLoginOptions serves POST
// /api/v1/auth/webauthn/login/generate-options for the user-named login path.
//
// An unknown account and an account with no passkeys currently produce the same
// 401 so this endpoint cannot be used to enumerate registered emails. Task 4.3
// replaces that with an indistinguishable mock challenge, which closes the
// remaining signal (that a 401 here means "not registered") entirely.
func (s *Server) handleWebAuthnLoginOptions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req webauthnLoginOptionsRequest
		if err := json.Unmarshal(body, &req); err != nil || req.Email == "" {
			writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "invalid_request"})
			return
		}

		options, err := s.deps.WebAuthn.BeginLogin(r.Context(), req.Email)
		if err != nil {
			s.writeWebAuthnLoginError(w, "begin login", err)
			return
		}
		writeJSON(w, http.StatusOK, options)
	}
}

// handleWebAuthnLoginVerify serves POST /api/v1/auth/webauthn/login/verify. On a
// valid assertion (verified origin, RP ID, signature, and a strictly increasing
// signature counter) it issues the hardened session cookie and returns 204; the
// cookie is the whole payload.
//
// Every failure collapses into an opaque 401 so a caller cannot distinguish a
// replayed challenge, a wrong origin, or a cloned authenticator. Clone
// detection is logged at warn level because it is a security event worth
// alerting on, per docs/architecture.md ("Signature Counter Auditing").
func (s *Server) handleWebAuthnLoginVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.deps.SessionManager == nil {
			// Unreachable in a wired process: main always builds both, and the
			// route is only mounted with a WebAuthn service present.
			s.logger.Error("webauthn: login verify reached without a session manager")
			writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
			return
		}

		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		userID, err := s.deps.WebAuthn.FinishLogin(r.Context(), body)
		if err != nil {
			s.writeWebAuthnLoginError(w, "finish login", err)
			return
		}

		if _, err := s.deps.SessionManager.Issue(w, session.IssueParams{
			UserID:    userID.String(),
			IP:        r.RemoteAddr,
			UserAgent: r.UserAgent(),
		}); err != nil {
			s.logger.Error("webauthn: issue session after login failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// webauthnSessionUser resolves the authenticated account's UUID from the request
// session. RequireSession guarantees a session is present, so both failure paths
// here indicate an internal inconsistency rather than an auth failure.
func (s *Server) webauthnSessionUser(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	current, ok := session.FromContext(r.Context())
	if !ok {
		s.logger.Error("webauthn: handler reached without a session in context")
		writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
		return uuid.Nil, false
	}

	userID, err := uuid.Parse(current.UserID)
	if err != nil {
		s.logger.Error("webauthn: session carries a non-UUID user id", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
		return uuid.Nil, false
	}
	return userID, true
}

// readWebAuthnBody reads a size-capped request body, writing a 400 and
// reporting false when it is unreadable or over the cap.
func (s *Server) readWebAuthnBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebAuthnBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "invalid_request"})
		return nil, false
	}
	return body, true
}

// writeWebAuthnRegistrationError maps a registration failure to a status code.
// Registration runs inside an authenticated session, so it can afford to
// distinguish a malformed body from a stale challenge (both are user-actionable:
// retry the ceremony) without leaking anything useful to an attacker.
func (s *Server) writeWebAuthnRegistrationError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, webauthn.ErrUserNotFound):
		// The session outlived its account (deleted mid-session).
		writeJSON(w, http.StatusUnauthorized, webauthnErrorResponse{Error: "unauthorized"})
	case errors.Is(err, webauthn.ErrInvalidResponse):
		writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "invalid_request"})
	case errors.Is(err, webauthn.ErrChallengeNotFound), errors.Is(err, webauthn.ErrChallengeExpired):
		writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "challenge_invalid"})
	case errors.Is(err, webauthn.ErrVerification):
		writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "verification_failed"})
	default:
		s.logger.Error("webauthn: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
	}
}

// writeWebAuthnLoginError collapses every login failure into an opaque 401,
// except a malformed body (400) and an unexpected internal fault (500). Nothing
// in the response distinguishes an unknown account, a passkey-less account, a
// consumed challenge, or a failed signature.
func (s *Server) writeWebAuthnLoginError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, webauthn.ErrInvalidResponse):
		writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "invalid_request"})
	case errors.Is(err, webauthn.ErrCredentialCloned):
		// A non-increasing signature counter means the private key may have
		// been extracted and cloned: log loudly, tell the client nothing.
		s.logger.Warn("webauthn: cloned authenticator detected; login rejected", "operation", op)
		writeJSON(w, http.StatusUnauthorized, webauthnErrorResponse{Error: "invalid_credentials"})
	case errors.Is(err, webauthn.ErrUserNotFound),
		errors.Is(err, webauthn.ErrNoCredentials),
		errors.Is(err, webauthn.ErrChallengeNotFound),
		errors.Is(err, webauthn.ErrChallengeExpired),
		errors.Is(err, webauthn.ErrVerification):
		writeJSON(w, http.StatusUnauthorized, webauthnErrorResponse{Error: "invalid_credentials"})
	default:
		s.logger.Error("webauthn: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
	}
}

// toWebAuthnCredentialResponse projects a stored credential into its public
// representation, dropping the public key and encoding the binary credential ID
// as unpadded base64url.
func toWebAuthnCredentialResponse(row db.WebauthnCredential) webauthnCredentialResponse {
	out := webauthnCredentialResponse{
		ID:              base64.RawURLEncoding.EncodeToString(row.ID),
		AAGUID:          row.Aaguid.String(),
		AttestationType: row.AttestationType,
		UserVerified:    row.UserVerified,
		BackupEligible:  row.BackupEligible,
		BackupState:     row.BackupState,
		SignCount:       row.SignCount,
	}
	if row.CreatedAt.Valid {
		out.CreatedAt = row.CreatedAt.Time
	}
	if row.LastUsedAt.Valid {
		lastUsed := row.LastUsedAt.Time
		out.LastUsedAt = &lastUsed
	}
	return out
}
