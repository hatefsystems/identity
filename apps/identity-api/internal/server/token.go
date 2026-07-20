package server

import (
	"errors"
	"mime"
	"net/http"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
)

// tokenErrorResponse is the RFC 6749 §5.2 error JSON body.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// handleToken serves POST /oauth2/token. It parses the form-encoded grant
// request, delegates to the token service, and serializes either the token
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

		resp, err := s.deps.TokenService.Exchange(r.Context(), r.PostForm)
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
