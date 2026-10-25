package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const portalSessionHeader = "X-Portal-Session"

// API responses do not pass through Next's document middleware. Enforce this
// policy at the actual response boundary, including early denials and 204s.
func (s *Server) browserBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api" {
			next.ServeHTTP(w, r)
			return
		}
		writer := &browserPolicyWriter{ResponseWriter: w}
		setBrowserResponsePolicy(writer.Header())
		// Admin retains its durable denial-audit transaction and existing Origin
		// allow-list. Its session gate applies the browser check inside that chain.
		if !strings.HasPrefix(r.URL.Path, "/api/v1/admin/") && r.URL.Path != "/api/v1/admin" {
			if !s.browserRequestAllowed(writer, r) {
				return
			}
		}
		next.ServeHTTP(writer, r)
	})
}

type browserPolicyWriter struct{ http.ResponseWriter }

func (w *browserPolicyWriter) WriteHeader(status int) {
	setBrowserResponsePolicy(w.Header())
	w.ResponseWriter.WriteHeader(status)
}

func (w *browserPolicyWriter) Write(p []byte) (int, error) {
	setBrowserResponsePolicy(w.Header())
	return w.ResponseWriter.Write(p)
}

func setBrowserResponsePolicy(header http.Header) {
	header.Set("Cache-Control", "private, no-store")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
}

func unsafeBrowserMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (s *Server) browserRequestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !unsafeBrowserMethod(r.Method) {
		return true
	}
	if s.cfg.PortalOrigin == "" {
		writeJSON(w, http.StatusServiceUnavailable, sessionErrorResponse{Error: "temporarily_unavailable"})
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != s.cfg.PortalOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeJSON(w, http.StatusForbidden, sessionErrorResponse{Error: "forbidden_origin"})
		return false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		var tooLarge *http.MaxBytesError
		status := http.StatusBadRequest
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, sessionErrorResponse{Error: "invalid_request"})
		return false
	}
	if len(body) == 0 {
		// Optional ceremony-options/logout bodies may be absent, including a
		// zero-byte chunked body. Whitespace is still an invalid JSON document.
		r.Body = http.NoBody
		return true
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeJSON(w, http.StatusUnsupportedMediaType, sessionErrorResponse{Error: "invalid_content_type"})
		return false
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || len(params) > 1 ||
		(len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		writeJSON(w, http.StatusUnsupportedMediaType, sessionErrorResponse{Error: "invalid_content_type"})
		return false
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(body) || !json.Valid(body) || !uniqueJSONFields(body) {
		writeJSON(w, http.StatusBadRequest, sessionErrorResponse{Error: "invalid_request"})
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return true
}

// Ambiguous duplicate names are rejected before either a nonce or one-use grant
// is consumed. Limit nesting independently of the byte bound.
func uniqueJSONFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		}
		return true
	}
	return value(0)
}

type browserSessionGuard struct{ server *Server }

func (g *browserSessionGuard) Handler(next http.Handler) http.Handler {
	return g.server.browserSessionHandler(next, false)
}

func (s *Server) browserLogout(next http.Handler) http.Handler {
	return s.browserSessionHandler(next, true)
}

func (s *Server) browserSessionHandler(next http.Handler, logout bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.SessionManager == nil {
			writeJSON(w, http.StatusServiceUnavailable, sessionErrorResponse{Error: "temporarily_unavailable"})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") && !s.browserRequestAllowed(w, r) {
			return
		}
		current, err := s.deps.SessionManager.Resolve(r)
		if logout && (errors.Is(err, session.ErrNoSession) || errors.Is(err, session.ErrSessionNotFound)) {
			s.deps.SessionManager.ClearCookie(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			s.writeBrowserSessionError(w, err)
			return
		}
		if current.Kind != session.KindAuthenticated || current.DPoPJKT == "" {
			s.writeBrowserSessionError(w, session.ErrSessionNotFound)
			return
		}
		intent := r.Header.Values(portalSessionHeader)
		if unsafeBrowserMethod(r.Method) || len(intent) > 0 {
			if len(intent) != 1 || intent[0] != current.ID {
				writeJSON(w, http.StatusConflict, sessionErrorResponse{Error: "session_changed"})
				return
			}
		}
		proof, ok := s.verifyBrowserProof(w, r, current.DPoPJKT)
		if !ok {
			return
		}
		r = r.WithContext(session.WithSession(dpop.WithProof(r.Context(), proof), current))
		if logout {
			next.ServeHTTP(w, r)
			return
		}
		if buffer, ok := w.(*adminResponseBuffer); ok {
			buffer.authenticatedSession = &current
			next.ServeHTTP(w, r)
			return
		}
		s.deps.SessionManager.TrackActivity(next).ServeHTTP(w, r)
	})
}

func (s *Server) browserLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, ok := s.verifyBrowserProof(w, r, "")
		if ok {
			next.ServeHTTP(w, r.WithContext(dpop.WithProof(r.Context(), proof)))
		}
	})
}

func (s *Server) verifyBrowserProof(w http.ResponseWriter, r *http.Request, expectedJKT string) (*dpop.Proof, bool) {
	if s.cfg.PortalOrigin == "" || s.deps.DPoPValidator == nil {
		writeJSON(w, http.StatusServiceUnavailable, sessionErrorResponse{Error: "temporarily_unavailable"})
		return nil, false
	}
	values := r.Header.Values(dpop.HeaderProof)
	if len(values) != 1 || values[0] == "" || strings.Contains(values[0], ",") || len(values[0]) > 16*1024 {
		s.writeBrowserDPoPError(w, r, dpop.ErrMalformedProof)
		return nil, false
	}
	proof, err := s.deps.DPoPValidator.Validate(r.Context(), values[0], dpop.VerifyParams{
		Realm: "browser:" + s.cfg.PortalOrigin, ExpectedJKT: expectedJKT,
		Method: r.Method, URL: s.cfg.PortalOrigin + r.URL.EscapedPath(), RequireNonce: true,
	})
	if err != nil {
		s.writeBrowserDPoPError(w, r, err)
		return nil, false
	}
	return proof, true
}

func (s *Server) writeBrowserSessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, session.ErrNoSession) || errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
		w.Header().Set("WWW-Authenticate", "Cookie")
		writeJSON(w, http.StatusUnauthorized, sessionErrorResponse{Error: "session_required"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, sessionErrorResponse{Error: "temporarily_unavailable"})
}

func (s *Server) writeBrowserDPoPError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, dpop.ErrStoreUnavailable) || errors.Is(err, dpop.ErrInvalidParams) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeJSON(w, http.StatusServiceUnavailable, sessionErrorResponse{Error: "temporarily_unavailable"})
		return
	}
	var challenge *dpop.NonceChallenge
	if errors.As(err, &challenge) {
		nonce, nonceErr := s.deps.DPoPValidator.IssueNonce(r.Context(), challenge.Realm, challenge.JKT)
		if nonceErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, sessionErrorResponse{Error: "temporarily_unavailable"})
			return
		}
		w.Header().Set(dpop.HeaderNonce, nonce)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		writeJSON(w, http.StatusUnauthorized, sessionErrorResponse{Error: "use_dpop_nonce"})
		return
	}
	w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
	writeJSON(w, http.StatusUnauthorized, sessionErrorResponse{Error: "invalid_dpop_proof"})
}
