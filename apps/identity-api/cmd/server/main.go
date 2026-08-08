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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clientauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
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

	dpopValidator, err := buildDPoPValidator()
	if err != nil {
		return err
	}

	sessionManager, err := buildSessionManager()
	if err != nil {
		return err
	}

	webauthnService, pool, err := buildWebAuthnService(cfg.Environment, logger)
	if err != nil {
		return err
	}
	if pool != nil {
		defer pool.Close()
	}

	srv := server.New(cfg, logger, server.Deps{
		OIDC:           oidcCfg,
		Keys:           keyManager,
		Clients:        clientRegistry,
		TokenService:   tokenService,
		DPoPValidator:  dpopValidator,
		SessionManager: sessionManager,
		WebAuthn:       webauthnService,
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

// buildDPoPValidator assembles the RFC 9449 DPoP validator used to
// sender-constrain tokens issued at /oauth2/token. It uses in-memory single-use
// jti replay tracking and a server-issued DPoP-Nonce store (the MVP backing;
// both sit behind interfaces so a Redis-backed guard — key dpop:jti:{jti},
// TTL 60s per docs/data-architecture.md §3.1 — can replace them cluster-wide
// without touching the validator).
func buildDPoPValidator() (*dpop.Validator, error) {
	validator, err := dpop.NewValidator(dpop.NewMemoryReplayGuard(), dpop.NewMemoryNonceStore())
	if err != nil {
		return nil, fmt.Errorf("main: build DPoP validator: %w", err)
	}
	return validator, nil
}

// buildSessionManager assembles the stateful browser-session lifecycle: the
// hardened __Host- cookie codec, the in-memory session store (the MVP backing;
// it sits behind the session.Store interface so a Redis-backed store — key
// session:token:{token_hash}, Hash type, 24h TTL per docs/data-architecture.md
// §3.1 — can replace it without touching the manager or handlers), and the
// Manager that owns the absolute/idle lifetime policy. Configuration (cookie
// name/Secure and the two TTLs) is loaded from the environment; the
// __Host-/Secure invariant is enforced inside NewCookieCodec so a misconfigured
// dev override fails fast at startup.
func buildSessionManager() (*session.Manager, error) {
	sc, err := config.LoadSession()
	if err != nil {
		return nil, err
	}

	codec, err := session.NewCookieCodec(session.CookieConfig{
		Name:   sc.CookieName,
		Secure: sc.CookieSecure,
		TTL:    sc.AbsoluteTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("main: build session cookie codec: %w", err)
	}

	manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
		AbsoluteTTL: sc.AbsoluteTTL,
		IdleTTL:     sc.IdleTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("main: build session manager: %w", err)
	}
	return manager, nil
}

// dbConnectTimeout bounds the startup connectivity probe against PostgreSQL so
// an unreachable database fails the boot quickly instead of hanging the process.
const dbConnectTimeout = 10 * time.Second

// buildWebAuthnService assembles the passkey ceremony service: the Relying Party
// identity from the environment, the sqlc-generated queries as the user and
// credential stores, and the in-memory challenge store (the MVP backing; it sits
// behind the webauthn.ChallengeStore interface so a Redis-backed store — key
// webauthn:challenge:{challenge} with the ceremony TTL per
// docs/data-architecture.md §3.1 — can replace it cluster-wide without touching
// the service).
//
// Unlike the other subsystems this one needs durable storage: credentials and
// the anonymised user handle live in PostgreSQL. When DATABASE_URL is unset the
// service is skipped entirely (returning a nil service, which leaves the passkey
// routes unmounted) so the rest of the API still boots for local work on
// unrelated endpoints — the same philosophy as the ephemeral development signing
// keys. Outside development a database is mandatory, so a missing DATABASE_URL
// is a startup error there.
//
// It returns the pool alongside the service so the caller owns its lifetime and
// can close it on shutdown.
func buildWebAuthnService(environment string, logger *slog.Logger) (*webauthn.Service, *pgxpool.Pool, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if environment != "development" {
			return nil, nil, fmt.Errorf("main: DATABASE_URL is required in %q environment", environment)
		}
		logger.Warn("no DATABASE_URL configured; WebAuthn passkey routes are disabled")
		return nil, nil, nil
	}

	wc, err := config.LoadWebAuthn(environment)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbConnectTimeout)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("main: open database pool: %w", err)
	}
	// Probe once at startup: a misconfigured DSN should fail the boot rather
	// than surface as a 500 on the first passkey ceremony.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("main: ping database: %w", err)
	}

	queries := db.New(pool)
	svc, err := webauthn.New(webauthn.Config{
		RPID:             wc.RPID,
		RPDisplayName:    wc.RPDisplayName,
		RPOrigins:        wc.RPOrigins,
		ChallengeTTL:     wc.ChallengeTTL,
		UserVerification: wc.UserVerification,
		ResidentKey:      wc.ResidentKey,
		MockChallengeKey: wc.MockChallengeKey,
		NamedLoginFloor:  wc.NamedLoginFloor,
	}, queries, queries, webauthn.NewMemoryChallengeStore(), webauthn.WithTransacter(pool))

	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("main: build webauthn service: %w", err)
	}

	logger.Info("webauthn relying party configured",
		slog.String("rp_id", wc.RPID),
		slog.Int("origins", len(wc.RPOrigins)),
		slog.String("user_verification", wc.UserVerification),
		slog.String("resident_key", wc.ResidentKey),
	)

	return svc, pool, nil
}
