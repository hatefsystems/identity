package session

import (
	"errors"
	"net/http"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
)

// RequireSession is chi/net-http compatible middleware that gates a route on a
// valid, sender-constrained server-side session. The transport must validate a
// proof against the resolved session's binding before populating DPoP context.
// Activity is renewed only after downstream authorization succeeds.
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
		sess, err := rs.manager.Resolve(r)
		if err != nil {
			writeSessionFailure(w, err)
			return
		}
		if sess.Kind != KindAuthenticated || sess.DPoPJKT == "" {
			rs.writeUnauthorized(w)
			return
		}

		// When the session was sender-constrained at issuance, require that the
		// request also carries a DPoP proof bound to the same key (RFC 9449).
		// A DPoP-bound session presented without a matching proof is treated as
		// a replay of a leaked cookie and rejected.
		proof := dpop.ProofFromContext(r.Context())
		if proof == nil || proof.JKT != sess.DPoPJKT {
			rs.writeUnauthorized(w)
			return
		}

		rs.manager.TrackActivity(next).ServeHTTP(w, r.WithContext(WithSession(r.Context(), sess)))
	})
}

// RequireRecoveryEnrollment gates the two dedicated replacement-passkey
// endpoints. It rejects full sessions as well as every other session kind.
type RequireRecoveryEnrollment struct {
	manager *Manager
}

// NewRequireRecoveryEnrollment constructs restricted-session middleware.
func NewRequireRecoveryEnrollment(manager *Manager) (*RequireRecoveryEnrollment, error) {
	if manager == nil {
		return nil, errors.New("session: manager is required")
	}
	return &RequireRecoveryEnrollment{manager: manager}, nil
}

// Handler wraps next with restricted recovery-session enforcement.
func (rs *RequireRecoveryEnrollment) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := rs.manager.Resolve(r)
		if err != nil {
			writeSessionFailure(w, err)
			return
		}
		if sess.Kind != KindRecoveryEnrollment {
			rs.writeUnauthorized(w)
			return
		}
		if sess.DPoPJKT != "" {
			proof := dpop.ProofFromContext(r.Context())
			if proof == nil || proof.JKT != sess.DPoPJKT {
				rs.writeUnauthorized(w)
				return
			}
		}
		rs.manager.TrackActivity(next).ServeHTTP(w, r.WithContext(WithSession(r.Context(), sess)))
	})
}

func (rs *RequireRecoveryEnrollment) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Cookie")
	w.WriteHeader(http.StatusUnauthorized)
}

// writeUnauthorized emits a cookie-based auth challenge. Unlike the DPoP
// resource-server profile there is no token scheme to name, so this is a plain
// 401 the SPA interprets as "re-authenticate".
func (rs *RequireSession) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Cookie")
	w.WriteHeader(http.StatusUnauthorized)
}

func writeSessionFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNoSession) || errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrAccountIneligible) {
		w.Header().Set("WWW-Authenticate", "Cookie")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeActivityUnavailable(w)
}
