package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

const webAuthnChallengeSubnetLimit = 30

// Login and reclaim share the same subnet budget. Run this before anonymous
// nonce/challenge allocation, including rejected proofs, not after Begin*.
func (s *Server) webAuthnChallengeAdmission(next http.Handler) http.Handler {
	return s.anonymousChallengeAdmission(next, "webauthn", webAuthnChallengeSubnetLimit)
}

// Bound every new login nonce allocation, including rejected proofs. This is
// independent of the stricter account, destination and primary-factor budgets.
func (s *Server) loginChallengeAdmission(next http.Handler) http.Handler {
	return s.anonymousChallengeAdmission(next, "login-admission", 120)
}

func (s *Server) anonymousChallengeAdmission(next http.Handler, namespace string, limit int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.WebAuthnLimiter == nil {
			if s.cfg.Environment == "development" {
				next.ServeHTTP(w, r)
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, webauthnErrorResponse{Error: "temporarily_unavailable"})
			return
		}
		subnet := sha256.Sum256([]byte(ratelimit.Subnet(clientip.FromRequest(r))))
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		allowed, err := s.deps.WebAuthnLimiter.Allow(ctx, "rate:"+namespace+":subnet:v1:"+hex.EncodeToString(subnet[:]),
			limit, time.Minute)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, webauthnErrorResponse{Error: "temporarily_unavailable"})
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, webauthnErrorResponse{Error: "rate_limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
