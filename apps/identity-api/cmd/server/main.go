// Command server is the entry point for the Hatef Identity Platform IdP
// backend (identity-api). It loads configuration from the environment, builds
// the OIDC signing keystore, starts the HTTP server, and shuts down gracefully
// on SIGINT/SIGTERM.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clientauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("server terminated with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// run wires up configuration and the server, then blocks until a termination
// signal is received and a graceful shutdown completes. It is separated from
// main so it can return errors instead of calling os.Exit directly.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	oidcCfg, err := config.LoadOIDC(cfg.Environment)
	if err != nil {
		return err
	}

	keyManager, err := buildKeyManager(oidcCfg, cfg.Environment, logger)
	if err != nil {
		return err
	}

	clientRegistry, err := config.LoadClients(cfg.Environment)
	if err != nil {
		return err
	}

	tokenService, err := buildTokenService(oidcCfg, keyManager, clientRegistry, logger)
	if err != nil {
		return err
	}

	srv := server.New(cfg, logger, server.Deps{
		OIDC:         oidcCfg,
		Keys:         keyManager,
		Clients:      clientRegistry,
		TokenService: tokenService,
	})

	// Listen for OS termination signals to trigger graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the server in a goroutine so we can wait on the signal context.
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	select {
	case err := <-serverErr:
		// Server stopped on its own (e.g. failed to bind the port).
		return err
	case <-ctx.Done():
		// Signal received; begin graceful shutdown.
		stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// buildKeyManager assembles the OIDC signing keystore. In production it parses
// the KMS-injected PEM key material for the active/next (and optional previous)
// rotation slots. In development, when no keys are injected, it generates
// ephemeral ES256 keys so the server can boot for local testing — these keys
// are process-local and never persisted.
func buildKeyManager(cfg config.OIDCConfig, environment string, logger *slog.Logger) (*keys.Manager, error) {
	if !cfg.HasKeys() {
		if environment != "development" {
			// LoadOIDC already enforces this, but guard defensively so a
			// production process can never come up with ephemeral keys.
			return nil, fmt.Errorf("main: signing keys are required in %q environment", environment)
		}
		logger.Warn("no OIDC signing keys configured; generating ephemeral development keys (do not use in production)")
		active, err := keys.NewEphemeralES256()
		if err != nil {
			return nil, err
		}
		next, err := keys.NewEphemeralES256()
		if err != nil {
			return nil, err
		}
		return keys.NewManager(active, next, nil)
	}

	active, err := keys.ParsePrivateKeyPEM(cfg.ActiveKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("main: parse active signing key: %w", err)
	}
	next, err := keys.ParsePrivateKeyPEM(cfg.NextKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("main: parse next signing key: %w", err)
	}

	var previous *keys.SigningKey
	if len(cfg.PreviousKeyPEM) > 0 {
		previous, err = keys.ParsePrivateKeyPEM(cfg.PreviousKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("main: parse previous signing key: %w", err)
		}
	}

	return keys.NewManager(active, next, previous)
}

// buildTokenService assembles the /oauth2/token service: in-memory code and
// refresh-token stores (the MVP backing; both sit behind interfaces so a Redis
// store can replace them later) plus the RFC 7523 private_key_jwt client
// authenticator for the client_credentials grant. The authenticator's expected
// audience is the fully-qualified token endpoint URL so an assertion minted for
// a different endpoint is rejected (audience-confusion defence).
func buildTokenService(
	oidcCfg config.OIDCConfig,
	keyManager *keys.Manager,
	clientRegistry *clients.StaticRegistry,
	logger *slog.Logger,
) (*token.Service, error) {
	tokenEndpoint := oidcCfg.Issuer + "/oauth2/token"
	authenticator, err := clientauth.New(clientRegistry, tokenEndpoint, clientauth.NewMemoryJTIGuard())
	if err != nil {
		return nil, fmt.Errorf("main: build client authenticator: %w", err)
	}

	svc, err := token.NewService(
		token.Config{Issuer: oidcCfg.Issuer},
		keyManager,
		clientRegistry,
		token.NewMemoryCodeStore(),
		token.NewMemoryRefreshTokenStore(),
		authenticator,
		nil,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("main: build token service: %w", err)
	}
	return svc, nil
}
