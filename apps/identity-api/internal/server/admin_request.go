package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const adminResponseLimit = 4 * 1024 * 1024

// No headers or bytes reach the client until the durable audit transaction
// commits. This deliberately does not implement Flusher or Hijacker.
type adminResponseBuffer struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (w *adminResponseBuffer) Header() http.Header { return w.header }
func (w *adminResponseBuffer) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *adminResponseBuffer) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if len(p) > adminResponseLimit-w.body.Len() {
		w.overflow = true
		return 0, errors.New("admin response exceeds limit")
	}
	return w.body.Write(p)
}

func (s *Server) adminTransaction(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Admin.RequestTimeout)
		defer cancel()
		op, err := s.deps.AdminActions.Begin(ctx)
		if err != nil {
			s.logger.Error("admin audit storage unavailable")
			s.writeAdminError(w, http.StatusServiceUnavailable, "audit_unavailable")
			return
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
			_ = op.Rollback(cleanup)
		}()
		op.Event = audit.Event{
			EventType: "admin.request", ActionStatus: audit.StatusSuccess,
			ActorSPIFFEID: audit.APIActorSPIFFEID,
			ClientIP:      clientip.FromRequest(r), UserAgent: r.UserAgent(),
		}
		r = r.WithContext(adminaction.WithContext(ctx, op))
		r.Body = http.MaxBytesReader(nil, r.Body, 64*1024)
		buffer := &adminResponseBuffer{header: make(http.Header)}
		func() {
			defer func() {
				if recover() != nil {
					buffer.body.Reset()
					buffer.status = 0
					s.writeAdminError(buffer, http.StatusInternalServerError, "server_error")
					s.logger.Error("admin request panic; transaction rolled back")
				}
			}()
			if !s.adminRateAllowed(buffer, r, "subnet:"+ratelimit.Subnet(clientip.FromRequest(r)), s.cfg.Admin.PerSubnetPerMinute) {
				return
			}
			if !s.adminOriginAllowed(r) {
				s.writeAdminError(buffer, http.StatusForbidden, "forbidden_origin")
				return
			}
			next.ServeHTTP(buffer, r)
		}()
		if buffer.status == 0 {
			buffer.status = http.StatusOK
		}
		if buffer.status >= 400 && buffer.body.Len() == 0 {
			status := buffer.status
			code := "server_error"
			switch status {
			case 401:
				code = "unauthorized"
			case 403:
				code = "forbidden"
			case 404:
				code = "not_found"
			case 405:
				code = "method_not_allowed"
			}
			buffer.status = 0
			s.writeAdminError(buffer, status, code)
		}
		if buffer.overflow {
			buffer.body.Reset()
			buffer.status = 0
			s.writeAdminError(buffer, http.StatusInternalServerError, "response_too_large")
		}
		if op.Event.Payload == nil {
			op.Event.Payload = make(map[string]any)
		}
		pattern := "/api/v1/admin/*"
		if route := chi.RouteContext(r.Context()); route != nil && route.RoutePattern() != "" {
			pattern = route.RoutePattern()
		}
		op.Event.Payload["operation"] = r.Method + " " + pattern
		op.Event.Payload["http_status"] = buffer.status
		restrictedWorkflow := adminaction.IsLegalWorkflowPath(r.URL.Path)
		if restrictedWorkflow {
			// This internal marker also survives the separate failure-audit
			// transaction. The sanitizer consumes it without persisting it.
			op.Event.Payload["workflow_restricted"] = true
		}
		if buffer.status >= 200 && buffer.status < 300 {
			if !restrictedWorkflow && !adminaction.IsLegalWorkflowOperation(r.Method+" "+pattern) {
				digest := sha256.Sum256(buffer.body.Bytes())
				op.Event.Payload["response_digest"] = hex.EncodeToString(digest[:])
			} else {
				delete(op.Event.Payload, "response_digest")
			}
			err = op.Commit(ctx)
			if err == nil && op.AfterCommit != nil {
				if cleanupErr := op.AfterCommit(); cleanupErr != nil {
					s.logger.Error("admin: local credential cleanup failed; durable account version enforced")
				}
			}
		} else {
			op.Event.ActionStatus = audit.StatusFailure
			failureCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			_ = op.Rollback(failureCtx)
			err = s.deps.AdminActions.Record(failureCtx, op.Event)
			stop()
		}
		if err != nil {
			s.logger.Error("admin durable audit failed; response withheld")
			s.writeAdminError(w, http.StatusServiceUnavailable, "audit_unavailable")
			return
		}
		for key, values := range buffer.header {
			w.Header()[key] = values
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}

func (s *Server) adminActorContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current, ok := session.FromContext(r.Context())
		if !ok {
			s.writeAdminError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		actor, err := uuid.Parse(current.UserID)
		if err != nil {
			s.writeAdminError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if op, exists := adminaction.FromContext(r.Context()); exists {
			op.Event.ActorID = actor
		}
		if !s.adminRateAllowed(w, r, "actor:"+actor.String(), s.cfg.Admin.PerActorPerMinute) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminRateAllowed(w http.ResponseWriter, r *http.Request, key string, limit int) bool {
	if s.deps.AdminLimiter == nil {
		s.writeAdminError(w, http.StatusServiceUnavailable, "rate_limit_unavailable")
		return false
	}
	allowed, err := s.deps.AdminLimiter.Allow(r.Context(), "rate:admin:"+key, limit, time.Minute)
	if err != nil {
		s.writeAdminError(w, http.StatusServiceUnavailable, "rate_limit_unavailable")
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(60))
		s.writeAdminError(w, http.StatusTooManyRequests, "rate_limited")
		return false
	}
	return true
}

func (s *Server) adminOriginAllowed(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	for _, allowed := range s.cfg.Admin.AllowedOrigins {
		if origin != "" && origin == allowed {
			return true
		}
	}
	return false
}
