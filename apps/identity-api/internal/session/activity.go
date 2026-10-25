package session

import (
	"errors"
	"io"
	"net/http"
)

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
		writer := &activityWriter{ResponseWriter: w, renew: func() error {
			_, err := m.renew(r, s)
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
		if err := w.renew(); err != nil && !errors.Is(err, ErrSessionNotFound) {
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
