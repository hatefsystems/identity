// Package server wires the HTTP router, middleware, and route handlers for the
// identity-api service. At this scaffolding stage it exposes health and
// readiness probes plus the OIDC discovery and JWKS endpoints; token,
// WebAuthn, and admin routes are added in later tasks.
package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// Deps carries the optional service dependencies injected into the Server.
// Fields left zero-valued disable the routes that need them, which keeps
// handler tests lightweight and startup order explicit.
type Deps struct {
	// OIDC provides the issuer identity used to build the discovery document.
	OIDC config.OIDCConfig
	// Keys is the signing keystore backing /oauth2/jwks; when nil, the OIDC
	// discovery and JWKS routes are not mounted.
	Keys *keys.Manager
}

// Server encapsulates the HTTP server, its configuration, and dependencies.
type Server struct {
	cfg    config.Config
	deps   Deps
	logger *slog.Logger
	router chi.Router
	http   *http.Server
}

// New constructs a Server, builds the router and registers routes. If logger is
// nil, a default JSON logger writing to stderr is used.
func New(cfg config.Config, logger *slog.Logger, deps Deps) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:    cfg,
		deps:   deps,
		logger: logger,
		router: chi.NewRouter(),
	}

	s.registerMiddleware()
	s.registerRoutes()

	s.http = &http.Server{
		Addr:         cfg.Addr(),
		Handler:      s.router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return s
}

// Handler exposes the underlying router, primarily for testing with httptest.
func (s *Server) Handler() http.Handler {
	return s.router
}

// registerMiddleware installs the base middleware chain. Security-specific
// middleware (strict-nonce CSP, DPoP, rate limiting) is layered on in later
// tasks.
func (s *Server) registerMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Recoverer)
}

// registerRoutes maps URL paths to handlers.
func (s *Server) registerRoutes() {
	s.router.Get("/healthz", s.handleLiveness())
	s.router.Get("/readyz", s.handleReadiness())

	// OIDC discovery and JWKS are only exposed when a signing keystore has
	// been provisioned; without keys there is nothing meaningful to publish.
	if s.deps.Keys != nil {
		s.registerOIDCRoutes()
	}
}

// Start begins serving HTTP requests and blocks until the server is shut down.
// It returns nil on a graceful shutdown triggered via http.ErrServerClosed.
func (s *Server) Start() error {
	s.logger.Info("http server listening", slog.String("addr", s.cfg.Addr()), slog.String("env", s.cfg.Environment))
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server, allowing in-flight requests to complete
// within the provided context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("http server shutting down")
	return s.http.Shutdown(ctx)
}
