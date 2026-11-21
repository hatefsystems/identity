package session

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
)

type securityChangeKey struct{}
type committedOutcomeKey struct{}

// HeaderAuthInvalidated reports a committed security change, never new authority.
const HeaderAuthInvalidated = "X-Identity-Auth-Invalidated"

// SecurityChangeCommitted preserves an already committed mutation's result.
// It never renews, restamps or otherwise restores the initiating authority.
func SecurityChangeCommitted(ctx context.Context) {
	if committed, ok := ctx.Value(securityChangeKey{}).(*atomic.Bool); ok {
		committed.Store(true)
	}
}

// OutcomeCommitted preserves a confirmed one-use result if renewal later fails.
// Unlike a security change, it neither invalidates nor restores session authority.
func OutcomeCommitted(ctx context.Context) {
	if committed, ok := ctx.Value(committedOutcomeKey{}).(*atomic.Bool); ok {
		committed.Store(true)
	}
}

// TrackActivity renews only requests which pass the downstream authorization
// gates. In particular a nonce challenge, failed step-up, RBAC denial, or invalid
// input cannot keep a session alive. No handler response is released on a failed
// renewal dependency; mutations may already have committed and must not be retried.
func (m *Manager) TrackActivity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := FromContext(r.Context())
		if !ok {
			writeActivityUnavailable(w)
			return
		}
		committed := &atomic.Bool{}
		outcome := &atomic.Bool{}
		r = r.WithContext(context.WithValue(r.Context(), securityChangeKey{}, committed))
		r = r.WithContext(context.WithValue(r.Context(), committedOutcomeKey{}, outcome))
		writer := &activityWriter{ResponseWriter: w, renew: func() error {
			if committed.Load() {
				w.Header().Set(HeaderAuthInvalidated, "true")
				// Recovery completion already clears its restricted cookie explicitly.
				if s.Kind != KindRecoveryEnrollment {
					m.ClearCookie(w)
				}
				return nil
			}
			_, err := m.renew(r, s)
			if err != nil && outcome.Load() {
				// Renewal cannot turn confirmed delivery/proof consumption into a
				// retryable failure or withhold the only usable ceremony handle.
				return nil
			}
			return err
		}}
		next.ServeHTTP(writer, r)
		if !writer.wrote {
			writer.WriteHeader(http.StatusOK)
		}
	})
}

type activityWriter struct {
	http.ResponseWriter
	renew  func() error
	wrote  bool
	failed bool
}

func (w *activityWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if status >= 200 && status < 300 {
		// An admitted request may race remote revocation, or may be signing out
		// itself. Neither case resurrects authority or cancels committed work.
		if err := w.renew(); err != nil && !errors.Is(err, ErrSessionNotFound) && !errors.Is(err, ErrAccountIneligible) {
			w.failed = true
			writeActivityUnavailable(w.ResponseWriter)
			return
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *activityWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.failed {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

func writeActivityUnavailable(w http.ResponseWriter) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, `{"error":"temporarily_unavailable"}`)
}
