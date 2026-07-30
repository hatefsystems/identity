package session

import (
	"errors"
	"net/http"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
)

// RequireSession is chi/net-http compatible middleware that gates a route on a
// valid server-side session. On success it slides the session's idle deadline
// forward (via Manager.Authenticate) and stores the resolved Session in the
// request context (SessionFromContext) for downstream handlers; on any failure
// it responds 401 and never calls next.
//
// This is the browser/first-party profile protecting the self-service account
// routes (docs/frontend-pages.md), distinct from the DPoP resource-server
// profile that guards machine API access. The two can compose: when a session
// is DPoP-bound (Session.DPoPJKT set at issuance) this middleware additionally
// checks the request's DPoP proof thumbprint matches, so a stolen cookie
// cannot be replayed without the corresponding private key.
type RequireSession struct {
	manager *Manager
}

// NewRequireSession constructs session-enforcement middleware over the given
// Manager.
func NewRequireSession(manager *Manager) (*RequireSession, error) {
	if manager == nil {
		return nil, errors.New("session: manager is required")
	}
	return &RequireSession{manager: manager}, nil
}

// Handler wraps next with session enforcement.
func (rs *RequireSession) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := rs.manager.Authenticate(r)
		if err != nil {
			// Both a missing cookie and an unknown/expired/revoked token are
			// reported uniformly so a probe cannot distinguish "no session"
			// from "session lapsed".
			rs.writeUnauthorized(w)
			return
		}

		// When the session was sender-constrained at issuance, require that the
		// request also carries a DPoP proof bound to the same key (RFC 9449).
		// A DPoP-bound session presented without a matching proof is treated as
		// a replay of a leaked cookie and rejected.
		if sess.DPoPJKT != "" {
			proof := dpop.ProofFromContext(r.Context())
			if proof == nil || proof.JKT != sess.DPoPJKT {
				rs.writeUnauthorized(w)
				return
			}
		}

		next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), sess)))
	})
}

// writeUnauthorized emits a cookie-based auth challenge. Unlike the DPoP
// resource-server profile there is no token scheme to name, so this is a plain
// 401 the SPA interprets as "re-authenticate".
func (rs *RequireSession) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Cookie")
	w.WriteHeader(http.StatusUnauthorized)
}
