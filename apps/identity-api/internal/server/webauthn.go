package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
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

type recoveryEnrollmentResponse struct {
	Next string `json:"next"`
}

// webauthnLoginOptionsRequest is the body of the login options request.
//
// Email is optional and selects the flow. Omitted or empty runs the
// discoverable (usernameless) ceremony, which is the primary path: no identity
// is named, so there is nothing to enumerate. Supplying an email runs the
// legacy user-named ceremony, which answers with a decoy rather than an error
// when the identity cannot sign in (docs/api-design.md §1.3).
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
// else's account.
//
// Key *deletion* is gated further, behind RequireStepUp: unenrolling an
// authenticator is how an attacker with a hijacked session locks the legitimate
// owner out, so it must cost a freshly re-asserted strong factor. It is left
// unmounted when no step-up service is configured rather than served ungated.
func (s *Server) registerWebAuthnRoutes() {
	// The guards are built once, before routing, because the account-scoped
	// routes must not be mounted at all if they cannot be constructed.
	guard, hasSession := s.sessionGuard("webauthn")
	stepGuard, hasStepUp := s.stepUpGuard("webauthn")

	s.router.Route("/api/v1/auth/webauthn", func(r chi.Router) {
		r.Post("/login/generate-options", s.handleWebAuthnLoginOptions())
		r.Post("/login/verify", s.handleWebAuthnLoginVerify())

		if !hasSession {
			return
		}
		// A nested group scopes RequireSession to the enrolment routes only,
		// leaving the login routes above reachable without a session.
		r.Group(func(pr chi.Router) {
			pr.Use(guard.Handler)
			pr.Get("/keys", s.handleWebAuthnListKeys())

			if !hasStepUp {
				return
			}
			// The single-use grant is consumed at ceremony start. Finish relies on
			// the pending challenge's exact session binding, so a second grant is
			// neither needed nor accepted.
			pr.With(stepGuard.Handler).Post("/register/generate-options", s.handleWebAuthnRegisterOptions())
			pr.Post("/register/verify", s.handleWebAuthnRegisterVerify())
			// Nested inside the session group so deletion requires both a live
			// session and a fresh step-up grant.
			pr.Group(func(sr chi.Router) {
				sr.Use(stepGuard.Handler)
				sr.Delete("/keys/{id}", s.handleWebAuthnDeleteKey())
			})
		})
	})

	if !hasSession {
		return
	}
	recoveryGuard, err := session.NewRequireRecoveryEnrollment(s.deps.SessionManager)
	if err != nil {
		s.logger.Error("webauthn: failed to build recovery enrollment guard", "error", err.Error())
		return
	}
	s.router.Route("/api/v1/auth/enrollment/webauthn/register", func(r chi.Router) {
		r.Use(recoveryGuard.Handler)
		r.Post("/generate-options", s.handleRecoveryWebAuthnRegisterOptions())
		r.Post("/verify", s.handleRecoveryWebAuthnRegisterVerify())
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

		current, _ := session.FromContext(r.Context())
		options, err := s.deps.WebAuthn.BeginRegistration(r.Context(), userID, current.ID)
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

		current, _ := session.FromContext(r.Context())
		row, err := s.deps.WebAuthn.FinishRegistration(r.Context(), userID, current.ID, body)
		if err != nil {
			s.writeWebAuthnRegistrationError(w, "finish registration", err)
			return
		}
		writeJSON(w, http.StatusCreated, toWebAuthnCredentialResponse(row))
	}
}

func (s *Server) handleRecoveryWebAuthnRegisterOptions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}
		current, _ := session.FromContext(r.Context())
		options, err := s.deps.WebAuthn.BeginRecoveryRegistration(r.Context(), userID, current.ID)
		if err != nil {
			s.writeWebAuthnRegistrationError(w, "begin recovery registration", err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, options)
	}
}

func (s *Server) handleRecoveryWebAuthnRegisterVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}
		current, _ := session.FromContext(r.Context())
		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		claimed, err := s.deps.SessionManager.ClaimRecoveryEnrollment(current.UserID, current.ID)
		if err != nil {
			s.logger.Error("webauthn: claim recovery enrollment failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
			return
		}
		if !claimed {
			writeJSON(w, http.StatusConflict, webauthnErrorResponse{Error: "enrollment_already_used"})
			return
		}

		_, err = s.deps.WebAuthn.FinishRecoveryRegistration(r.Context(), userID, current.ID, body)
		if err != nil {
			if isConclusiveWebAuthnCeremonyFailure(err) {
				_ = s.deps.SessionManager.ReleaseRecoveryEnrollment(current.UserID, current.ID)
			}
			s.writeWebAuthnRegistrationError(w, "finish recovery registration", err)
			return
		}

		if err := s.deps.SessionManager.Revoke(w, r); err != nil {
			s.logger.Error("webauthn: clear completed recovery session failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, recoveryEnrollmentResponse{Next: "login"})
	}
}

func isConclusiveWebAuthnCeremonyFailure(err error) bool {
	return errors.Is(err, webauthn.ErrInvalidResponse) ||
		errors.Is(err, webauthn.ErrChallengeNotFound) ||
		errors.Is(err, webauthn.ErrChallengeExpired) ||
		errors.Is(err, webauthn.ErrChallengeFlowMismatch) ||
		errors.Is(err, webauthn.ErrVerification) ||
		errors.Is(err, webauthn.ErrUserVerificationRequired)
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
// /api/v1/auth/webauthn/login/generate-options for both login paths.
//
// With no email (or an empty one) it runs the discoverable ceremony: the
// response is identical for every caller because the server resolves nothing
// before answering. With an email it runs the user-named ceremony, which is
// account-harvesting resistant in a different way — an identity that cannot sign
// in gets a decoy ceremony rather than an error, so a 200 here says nothing
// about whether the account exists (docs/api-design.md §1.3,
// docs/frontend-pages.md §5.4).
//
// An empty body is accepted and treated as the discoverable flow, so a client
// that has nothing to send does not have to POST "{}".
func (s *Server) handleWebAuthnLoginOptions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readWebAuthnBody(w, r)
		if !ok {
			return
		}

		var req webauthnLoginOptionsRequest
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, webauthnErrorResponse{Error: "invalid_request"})
				return
			}
		}

		var (
			options *protocol.CredentialAssertion
			err     error
			op      string
		)
		if email := strings.TrimSpace(req.Email); email == "" {
			op = "begin discoverable login"
			options, err = s.deps.WebAuthn.BeginDiscoverableLogin(r.Context())
		} else {
			op = "begin login"
			options, err = s.deps.WebAuthn.BeginLogin(r.Context(), email)
		}
		if err != nil {
			s.writeWebAuthnLoginError(w, op, err)
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
			IP:        clientip.FromRequest(r),
			UserAgent: r.UserAgent(),
		}); err != nil {
			s.logger.Error("webauthn: issue session after login failed", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleWebAuthnDeleteKey serves DELETE /api/v1/auth/webauthn/keys/{id}, removing
// one of the authenticated account's registered authenticators. Step-up gated:
// see registerWebAuthnRoutes.
//
// The {id} path parameter is the unpadded base64url credential ID exactly as
// returned by GET /keys. Deletion is scoped to the caller's account inside the
// service, and refuses to remove the account's last remaining passkey. WebAuthn
// is currently the only session-issuing login method, so secondary factors do
// not satisfy this invariant.
func (s *Server) handleWebAuthnDeleteKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.webauthnSessionUser(w, r)
		if !ok {
			return
		}

		credentialID, err := base64.RawURLEncoding.DecodeString(chi.URLParam(r, "id"))
		if err != nil || len(credentialID) == 0 {
			// A malformed ID cannot name any credential, so it is reported the
			// same way as one that names none: nothing distinguishes "bad
			// encoding" from "not yours".
			writeJSON(w, http.StatusNotFound, webauthnErrorResponse{Error: "credential_not_found"})
			return
		}

		if err := s.deps.WebAuthn.DeleteCredential(r.Context(), userID, credentialID); err != nil {
			s.writeWebAuthnDeleteError(w, err)
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
		errors.Is(err, webauthn.ErrVerification),
		// The caller completed a decoy ceremony. Rendering it exactly like a
		// failed real assertion is the entire point: any distinct status or
		// code here would re-expose whether the named account exists.
		errors.Is(err, webauthn.ErrMockChallenge),
		// A suspended, unverified, or pending-deletion account. Also opaque:
		// "this account is banned" is itself an existence oracle.
		errors.Is(err, webauthn.ErrAccountNotActive),
		errors.Is(err, webauthn.ErrChallengeFlowMismatch):
		writeJSON(w, http.StatusUnauthorized, webauthnErrorResponse{Error: "invalid_credentials"})

	default:
		s.logger.Error("webauthn: "+op+" failed", "error", err.Error())
		writeJSON(w, http.StatusInternalServerError, webauthnErrorResponse{Error: "server_error"})
	}
}

// writeWebAuthnDeleteError maps a key-deletion failure to a status code.
//
// A credential that does not exist and one owned by another account render
// identically as 404, so the endpoint cannot be used to probe for credential IDs.
// The last-factor refusal is a 409 with a distinct code because it is the one
// outcome the user must understand to act on: enrol another passkey, enable TOTP,
// or set a password, then retry.
func (s *Server) writeWebAuthnDeleteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webauthn.ErrCredentialNotFound):
		writeJSON(w, http.StatusNotFound, webauthnErrorResponse{Error: "credential_not_found"})
	case errors.Is(err, webauthn.ErrLastCredential):
		writeJSON(w, http.StatusConflict, webauthnErrorResponse{Error: "last_credential"})
	case errors.Is(err, webauthn.ErrUserNotFound):
		// The session outlived its account (deleted mid-session).
		writeJSON(w, http.StatusUnauthorized, webauthnErrorResponse{Error: "unauthorized"})
	default:
		s.logger.Error("webauthn: delete credential failed", "error", err.Error())
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
