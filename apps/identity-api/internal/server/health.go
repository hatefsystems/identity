package server

import (
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
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Status:  "ok",
			Service: serviceName,
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// handleReadiness reports whether the service is ready to accept requests.
// At this scaffolding stage there are no backing dependencies (PostgreSQL,
// Redis, NATS) wired in yet, so it mirrors the liveness result. Dependency
// checks will be added here as those integrations land in later tasks.
func (s *Server) handleReadiness() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
