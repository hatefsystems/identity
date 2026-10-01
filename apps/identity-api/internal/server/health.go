package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// healthResponse is the JSON body returned by the health and readiness probes.
type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Time    string `json:"time"`
}

// serviceName identifies this service in health payloads.
const serviceName = "identity-api"

// handleLiveness reports whether the process is up and able to serve traffic.
// It performs no dependency checks and should always return 200 while the
// process is running, making it suitable for a Kubernetes liveness probe.
func (s *Server) handleLiveness() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Status:  "ok",
			Service: serviceName,
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// handleReadiness reports whether the service is ready to accept requests.
// Enabled admin capabilities require their gates and live dependency probe.
func (s *Server) handleReadiness() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Admin.Enabled {
			ready := s.deps.AdminActions != nil && s.deps.AdminStore != nil && s.deps.RBAC != nil &&
				s.deps.AdminLimiter != nil && s.deps.SessionManager != nil && s.deps.LegalHold != nil && s.deps.AdminReady != nil
			if ready {
				ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
				ready = s.deps.AdminReady(ctx) == nil
				cancel()
			}
			if !ready {
				writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready", Service: serviceName, Time: time.Now().UTC().Format(time.RFC3339)})
				return
			}
		}
		writeJSON(w, http.StatusOK, healthResponse{
			Status:  "ready",
			Service: serviceName,
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// writeJSON serializes v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// Errors here mean the client connection is already broken; there is
	// nothing actionable to do beyond letting the request terminate.
	_ = json.NewEncoder(w).Encode(v)
}
