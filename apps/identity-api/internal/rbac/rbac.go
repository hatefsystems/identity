// Package rbac provides the permission-enforcement middleware guarding the
// administrative surface at /api/v1/admin/* (docs/api-design.md §1.7).
//
// The model is permission-based, not role-based. A route declares the
// capability it needs (for example "admin.users.status.write") and the guard
// resolves it through the seeded roles -> role_permissions -> permissions graph
// with a single UserHasPermission round trip. Changing who may do what is
// therefore a role_permissions row (migration 00007), never a Go edit. Encoding
// role names in handlers would have the opposite property: every capability
// change would need a deploy, and the four roles in docs/architecture.md would
// harden into the only roles that can ever exist.
//
// # Fail closed
//
// Every path that is not an affirmative "yes" denies. A store error is 503, not
// a pass: an admin endpoint that opens up when the database is unhealthy is a
// strictly worse failure than one that is briefly unavailable. This mirrors the
// route-mounting doctrine in internal/server (server.go:293), where an absent
// gate means an absent route rather than an ungated one.
//
// # No caching
//
// Permission results are deliberately not cached. A revoked grant must take
// effect on the caller's next request; any cache turns that into a TTL window
// during which a demoted or compromised admin retains authority. Adding one is
// a security-relevant decision that needs its own invalidation story, so it is
// intentionally out of scope here.
//
// # Deny responses carry no information
//
// "No session user", "permission not held", and "unknown permission id" all
// render as a byte-identical 403 {"error":"forbidden"}. Distinguishing them
// would let a caller enumerate the capability model — probing which permission
// ids exist, and which of them it is merely missing — from the outside. Only
// the server log and the audit trail tell the causes apart.
package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// PermissionChecker is the narrow slice of the generated query surface this
// package needs. *db.Queries satisfies it; tests supply a fake.
type PermissionChecker interface {
	UserHasPermission(ctx context.Context, arg db.UserHasPermissionParams) (bool, error)
}

// contextKey is an unexported type for this package's context keys so values
// stored here cannot collide with keys from other packages.
type contextKey int

const actorContextKey contextKey = iota

// WithActor returns a copy of ctx carrying the authorized administrator's ID.
func WithActor(ctx context.Context, actor uuid.UUID) context.Context {
	return context.WithValue(ctx, actorContextKey, actor)
}

// ActorFromContext returns the administrator resolved by RequirePermission and
// true, or uuid.Nil and false when the request did not pass the guard.
//
// Handlers use this instead of re-parsing session.UserID: the guard has already
// validated and parsed it, and a second parse is a second chance to disagree
// about who the actor is in an audit record.
func ActorFromContext(ctx context.Context) (uuid.UUID, bool) {
	actor, ok := ctx.Value(actorContextKey).(uuid.UUID)
	return actor, ok
}

// errorResponse is the single deny/error body shape for this package.
type errorResponse struct {
	Error string `json:"error"`
}

// RequirePermission is chi/net-http compatible middleware gating a route on one
// RBAC permission.
//
// It must be composed *after* session.RequireSession: it reads the caller from
// the request context rather than establishing identity itself. It must be
// composed *before* stepup.RequireStepUp so an unauthorized caller is never
// induced to burn a single-use step-up grant on a route it cannot reach anyway.
type RequirePermission struct {
	checker    PermissionChecker
	permission string
	logger     *slog.Logger
	recorder   audit.Recorder
}

// Option customizes a RequirePermission.
type Option func(*RequirePermission)

// WithRecorder attaches an audit recorder so every denial raises
// audit.EventAdminAccessDenied.
//
// This is the tripwire for a compromised or over-curious admin account: a
// legitimate operator essentially never trips a permission check, so a burst of
// these is signal rather than noise. A nil recorder degrades to no auditing
// rather than to a closed route, matching server.Deps.AuditRecorder: auditing
// observes a working guard, it does not make the guard work.
func WithRecorder(r audit.Recorder) Option {
	return func(g *RequirePermission) { g.recorder = r }
}

// NewRequirePermission constructs permission-enforcement middleware for one
// permission id. A nil logger falls back to slog.Default.
func NewRequirePermission(checker PermissionChecker, permission string, logger *slog.Logger, opts ...Option) (*RequirePermission, error) {
	if checker == nil {
		return nil, errors.New("rbac: permission checker is required")
	}
	if permission == "" {
		return nil, errors.New("rbac: permission id is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	g := &RequirePermission{checker: checker, permission: permission, logger: logger}
	for _, opt := range opts {
		opt(g)
	}
	return g, nil
}

// Permission returns the permission id this guard enforces.
func (g *RequirePermission) Permission() string { return g.permission }

// Handler wraps next with permission enforcement.
func (g *RequirePermission) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := session.FromContext(r.Context())
		if !ok {
			// RequireSession guarantees a session. Reaching here means the
			// middleware chain was assembled wrongly, which is a programming
			// error, not an authorization failure — so it must not render as
			// 403, which would make a wiring bug look like a policy decision
			// and send an operator hunting through role grants. Same treatment
			// as stepup.RequireStepUp (middleware.go:52).
			g.logger.Error("rbac: middleware reached without a session in context",
				slog.String("method", r.Method),
				slog.String("permission", g.permission))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Defense in depth: session.RequireSession already rejects every kind
		// other than KindAuthenticated (middleware.go:46). This repeats the
		// check because the consequence of the two drifting apart is an
		// anonymous holder of one recovery code reaching an admin route, and
		// this package must not depend on another package's guard to prevent
		// that.
		if sess.Kind != session.KindAuthenticated {
			g.logger.Warn("rbac: restricted recovery session rejected at admin route",
				slog.String("method", r.Method),
				slog.String("permission", g.permission))
			g.deny(w, r, uuid.Nil, "restricted_session")
			return
		}

		actor, err := uuid.Parse(sess.UserID)
		if err != nil {
			// Every session subject is a users.id UUID. A non-UUID here means
			// a session was minted by something that disagrees about the
			// subject format; it is unresolvable, not unauthorized.
			g.logger.Error("rbac: session user id is not a uuid",
				slog.String("method", r.Method),
				slog.String("permission", g.permission))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		checker := g.checker
		if op, ok := adminaction.FromContext(r.Context()); ok {
			checker = op.Queries
		}
		allowed, err := checker.UserHasPermission(r.Context(), db.UserHasPermissionParams{
			UserID:       actor,
			PermissionID: g.permission,
		})
		if err != nil {
			// Fail closed. 503 (not 403) because the request was never
			// evaluated: reporting "forbidden" would tell the caller a policy
			// decision was made when none was, and would hide a database
			// outage behind what looks like a permissions problem.
			g.logger.Error("rbac: permission check failed",
				slog.String("method", r.Method),
				slog.String("permission", g.permission),
				slog.String("actor_id", actor.String()))
			g.writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "service_unavailable"})
			return
		}
		if !allowed {
			g.deny(w, r, actor, "permission_denied")
			return
		}

		next.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
}

// deny records the attempt and writes the uniform 403.
//
// reason is carried into the audit payload and the server log only. It never
// reaches the response body — see the package doc on why every denial must look
// identical from outside.
func (g *RequirePermission) deny(w http.ResponseWriter, r *http.Request, actor uuid.UUID, reason string) {
	g.recordDenial(r, actor, reason)
	g.writeJSON(w, http.StatusForbidden, errorResponse{Error: "forbidden"})
}

// recordDenial emits audit.EventAdminAccessDenied.
//
// The event is audit-only and never ledgered (see the LedgerEventTypes note in
// internal/audit): security_event_ledger.account_ref is the *subject* of an
// event, whereas the account here is the actor, so a ledger row would attribute
// an administrator's failed probe to whichever user happened to share the ID.
func (g *RequirePermission) recordDenial(r *http.Request, actor uuid.UUID, reason string) {
	if r == nil {
		return
	}
	e := audit.Event{
		EventType:     audit.EventAdminAccessDenied,
		ActionStatus:  audit.StatusFailure,
		ActorID:       actor,
		ActorSPIFFEID: audit.APIActorSPIFFEID,
		ClientIP:      clientip.FromRequest(r),
		Payload: map[string]any{
			"permission": g.permission,
			"reason":     reason,
			"method":     r.Method,
		},
	}
	e.UserAgent = r.UserAgent()
	if _, ok := adminaction.FromContext(r.Context()); ok {
		adminaction.SetEvent(r.Context(), e)
		return
	}
	if g.recorder == nil {
		return
	}

	ctx := r.Context()
	if err := g.recorder.Record(ctx, e); err != nil {
		// An audit transport failure must not change the HTTP outcome; the
		// caller is being denied either way.
		g.logger.Warn("rbac: record access-denied event",
			slog.String("permission", g.permission),
			slog.String("error", err.Error()))
	}
}

// writeJSON writes a JSON body with the given status.
//
// Cache-Control: no-store because an authorization decision is specific to one
// caller at one instant; a cached 403 could outlive the grant that would have
// made it a 200, and a cached 200 is worse.
func (g *RequirePermission) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// A write failure means the client is already gone; nothing useful remains.
	_ = json.NewEncoder(w).Encode(body)
}
