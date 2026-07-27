package server

import (
	"errors"
	"mime"
	"net/http"

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

		writeJSON(w, http.StatusOK, resp)
	}
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
