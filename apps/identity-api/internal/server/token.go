package server

import (
	"errors"
	"mime"
	"net/http"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
)

// tokenErrorResponse is the RFC 6749 §5.2 error JSON body. The optional
// dpop-nonce related error code (use_dpop_nonce) reuses the same envelope
// (RFC 9449 §5.2).
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// handleToken serves POST /oauth2/token. It parses the form-encoded grant
// request, optionally validates a DPoP proof to sender-constrain the issued
// token, delegates to the token service, and serializes either the token
// response or an RFC 6749 error. Responses carry Cache-Control: no-store
// (RFC 6749 §5.1) because they contain credentials.
func (s *Server) handleToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			writeJSON(w, http.StatusBadRequest, tokenErrorResponse{
				Error:            token.ErrCodeInvalidRequest,
				ErrorDescription: "Content-Type must be application/x-www-form-urlencoded",
			})
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, tokenErrorResponse{
				Error:            token.ErrCodeInvalidRequest,
				ErrorDescription: "malformed request body",
			})
			return
		}

		// DPoP sender-constraining (RFC 9449). When the client presents a DPoP
		// proof header, validate it against this endpoint and bind the issued
		// token to the proof's key via the request context. A proof is optional
		// here — a client that does not present one receives a plain Bearer
		// token — but a malformed/replayed proof, or a missing server nonce, is
		// rejected before any grant processing.
		ctx := r.Context()
		if proofHeader := r.Header.Get(dpop.HeaderProof); proofHeader != "" && s.deps.DPoPValidator != nil {
			proof, dErr := s.validateTokenDPoP(r, proofHeader)
			if dErr != nil {
				s.writeTokenDPoPError(w, r, dErr)
				return
			}
			ctx = dpop.WithProof(ctx, proof)
		}

		resp, err := s.deps.TokenService.Exchange(ctx, r.PostForm)
		if err != nil {
			s.recordTokenDenied(r, err)
			var tokenErr *token.Error
			if errors.As(err, &tokenErr) {
				writeJSON(w, tokenErr.Status, tokenErrorResponse{
					Error:            tokenErr.Code,
					ErrorDescription: tokenErr.Description,
				})
				return
			}
			s.logger.Error("token endpoint: unexpected error", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, tokenErrorResponse{
				Error: token.ErrCodeServerError,
			})
			return
		}

		s.recordTokenIssued(r, resp)
		writeJSON(w, http.StatusOK, resp)
	}
}

// recordTokenIssued records a successful grant.
//
// It is ledgered (Class B) only when the grant resolved a user account. The
// client_credentials grant has no subject — the client acts on its own behalf —
// so it produces an audit row with no subject and no security_event_ledger row,
// because account_ref is NOT NULL and there is no account to attribute. Inventing
// one would put a non-existent subject into the tamper-evident chain.
func (s *Server) recordTokenIssued(r *http.Request, resp *token.Response) {
	if resp == nil {
		return
	}
	e := audit.Event{
		EventType:    audit.EventTokenIssued,
		ActionStatus: audit.StatusSuccess,
		Payload: map[string]any{
			"grant_type": tokenAuditGrantType(r.PostForm.Get("grant_type")),
			"client_id":  resp.ClientID,
			"scope":      resp.Scope,
			// Records whether the issued token is sender-constrained, which is the
			// difference between a stolen token being replayable and not.
			"dpop_bound": r.Header.Get(dpop.HeaderProof) != "",
		},
	}
	// A malformed subject is treated as no subject rather than dropping the event:
	// the grant did happen, and the client/scope context is still worth recording.
	if subject, parseErr := uuid.Parse(resp.Subject); parseErr == nil {
		e.ActorID = subject
		e.SubjectID = &subject
		e.Security = &audit.SecurityContext{
			AccountRef: subject,
			ClientID:   resp.ClientID,
			Scope:      resp.Scope,
		}
	} else if resp.Subject != "" {
		s.logger.Error("token endpoint: issued response carries a non-UUID subject",
			"error", parseErr.Error())
	}
	s.record(r, e)
}

// recordTokenDenied records a refused grant.
//
// Audit-only, and with ActorID left as uuid.Nil: a denial usually has no resolved
// account (bad code, unknown client, failed client authentication), and the actor
// is the OAuth client rather than a user. ActorSPIFFEID, filled in by record,
// states which workload refused it, so a nil actor here is not confusable with the
// purge worker's nil actor.
//
// client_id comes from the raw form and may be unregistered or absent — that is
// precisely what makes it worth recording — so it is length-clamped rather than
// trusted. No token, code, assertion, or client secret from the form is recorded.
func (s *Server) recordTokenDenied(r *http.Request, err error) {
	reason := token.ErrCodeServerError
	var tokenErr *token.Error
	if errors.As(err, &tokenErr) {
		reason = tokenErr.Code
	}
	s.record(r, audit.Event{
		EventType:    audit.EventTokenDenied,
		ActionStatus: audit.StatusFailure,
		Payload: map[string]any{
			"grant_type": tokenAuditGrantType(r.PostForm.Get("grant_type")),
			"client_id":  clampAuditValue(r.PostForm.Get("client_id")),
			// tokenErr.Code is a server-defined RFC 6749 constant, never client
			// input, so it is safe to record verbatim. Description is not: it can
			// quote request detail.
			"reason": reason,
		},
	})
}

// tokenAuditGrantType clamps the client-supplied grant_type to the values the
// service implements, so an unbounded request field cannot choose the contents of
// an audit payload. Anything else is recorded as unsupported, which is the same
// distinction the endpoint itself makes.
func tokenAuditGrantType(grant string) string {
	switch grant {
	case token.GrantAuthorizationCode:
		return token.GrantAuthorizationCode
	case token.GrantRefreshToken:
		return token.GrantRefreshToken
	case token.GrantClientCredentials:
		return token.GrantClientCredentials
	case "":
		return "missing"
	default:
		return "unsupported"
	}
}

// clampAuditValue bounds a request-supplied string recorded in an audit payload.
//
// Some fields (an unregistered client_id) are only useful verbatim, so they cannot
// be mapped to a fixed vocabulary the way grant_type is. Truncating instead keeps a
// caller from choosing the size of a row in an append-only table.
func clampAuditValue(v string) string {
	const maxAuditValueLen = 128
	if len(v) <= maxAuditValueLen {
		return v
	}
	return v[:maxAuditValueLen] + "…"
}

// validateTokenDPoP validates a DPoP proof for the token endpoint. The htu is
// the canonical token endpoint URL derived from the issuer (audience-confusion
// defence), not the raw request URL: TLS is terminated at the reverse proxy so
// r.URL carries no scheme/host, and pinning the issuer-derived URL means a
// proof minted for a different endpoint is rejected. RequireNonce enforces the
// server-issued DPoP-Nonce lifecycle (RFC 9449 §8).
func (s *Server) validateTokenDPoP(r *http.Request, proofHeader string) (*dpop.Proof, error) {
	return s.deps.DPoPValidator.Validate(r.Context(), proofHeader, dpop.VerifyParams{
		Method:       http.MethodPost,
		URL:          s.deps.OIDC.Issuer + "/oauth2/token",
		RequireNonce: true,
	})
}

// writeTokenDPoPError translates a DPoP validation failure into an RFC 9449
// §5.2 token endpoint error. A missing/invalid server nonce yields HTTP 400
// use_dpop_nonce together with a fresh DPoP-Nonce header the client echoes on
// retry; every other failure is an opaque 400 invalid_dpop_proof.
func (s *Server) writeTokenDPoPError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, dpop.ErrNonceRequired) {
		if nonce, nErr := s.deps.DPoPValidator.IssueNonce(r.Context()); nErr == nil && nonce != "" {
			w.Header().Set(dpop.HeaderNonce, nonce)
		}
		writeJSON(w, http.StatusBadRequest, tokenErrorResponse{
			Error:            "use_dpop_nonce",
			ErrorDescription: "authorization server requires nonce in DPoP proof",
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, tokenErrorResponse{
		Error:            "invalid_dpop_proof",
		ErrorDescription: "DPoP proof validation failed",
	})
}
