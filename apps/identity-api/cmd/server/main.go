// Command server is the entry point for the Hatef Identity Platform IdP
// backend (identity-api). It loads configuration from the environment, builds
// the OIDC signing keystore, starts the HTTP server, and shuts down gracefully
// on SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clientauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
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
func run(logger *slog.Logger) (runErr error) {
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

	webauthnService, pool, err := buildWebAuthnService(cfg.Environment, logger)
	if err != nil {
		return err
	}
	if pool != nil {
		defer pool.Close()
	}
	var accounts session.AccountState
	if pool != nil {
		accounts = session.NewDBAccountState(pool)
	}
	redisClient, err := buildRedisClient(cfg.Environment, logger)
	if err != nil {
		return err
	}
	if redisClient != nil {
		defer func() { _ = redisClient.Close() }()
	}
	if cfg.GRPC.Enabled && (pool == nil || redisClient == nil) {
		return errors.New("main: enabled gRPC requires DATABASE_URL and REDIS_URL")
	}
	sessionManager, err := buildSessionManager(accounts, redisClient)
	if err != nil {
		return err
	}
	revokeUser := func(ctx context.Context, userID string) error {
		// Persistent invalidation precedes cache cleanup and fences in-flight
		// ceremonies through the existing auth-epoch trigger.
		if pool != nil {
			id, err := uuid.Parse(userID)
			if err != nil {
				return errors.New("main: invalid revocation subject")
			}
			if err := db.New(pool).RevokeUserCredentials(ctx, id); err != nil {
				return err
			}
		}
		return sessionManager.RevokeAllForUser(ctx, userID)
	}
	tokenService, refreshTokenStore, err := buildTokenService(oidcCfg, keyManager, clientRegistry, logger, accounts, sessionManager, redisClient, revokeUser)
	if err != nil {
		return err
	}
	dpopValidator, err := buildDPoPValidator(redisClient)
	if err != nil {
		return err
	}

	// The SMS OTP service shares the WebAuthn database pool (it persists the
	// verified phone) and the Redis client (rate limiting + code store). When
	// either backing store is absent in development the service is skipped and
	// its routes are left unmounted.
	smsotpService, err := buildSMSOTPService(cfg.Environment, pool, redisClient, logger)
	if err != nil {
		return err
	}

	// The TOTP MFA service reuses the WebAuthn database pool. When no database
	// is configured (development only) it is skipped and its routes are left
	// unmounted.
	mfaService, err := buildMFAService(pool, logger)
	if err != nil {
		return err
	}

	// The recovery-code service reuses the WebAuthn database pool and, when
	// present, the Redis client for its optional rate limits. When no database
	// is configured (development only) it is skipped and its routes are left
	// unmounted.
	recoveryService, recoveryFlow, err := buildRecoveryService(cfg.Environment, pool, redisClient, logger)
	if err != nil {
		return err
	}

	// The step-up service reuses the WebAuthn database pool, the OIDC keystore
	// (grants are signed by the same rotating keys as access tokens), and both
	// factor verifiers built above. When no database is configured (development
	// only) it is skipped, which also leaves every step-up-gated route
	// unmounted — the fail-closed behaviour documented on server.Deps.StepUp.
	stepupService, err := buildStepUpService(
		cfg.Environment, pool, redisClient, keyManager, oidcCfg, webauthnService, mfaService, logger)
	if err != nil {
		return err
	}

	// The audit transport is built before the services that record through it so a
	// single recorder — one bounded buffer, one publishing goroutine, one drop
	// counter — is shared by the HTTP handlers and the privacy service.
	auditRecorder, closeAudit, err := buildAuditRecorder(context.Background(), cfg.Environment, logger)
	if err != nil {
		return err
	}
	var grpcServer *privateGRPC
	defer func() {
		runErr = errors.Join(runErr, drainAuditRecorder(closeAudit, cfg.ShutdownTimeout, logger))
		if grpcServer != nil {
			runErr = errors.Join(runErr, grpcServer.Close())
		}
	}()

	// Capture attribution before ordinary security events cross the async boundary.
	if pool != nil && os.Getenv(config.EnvBlindIndexPepper) != "" {
		pepper, err := config.LoadBlindIndexPepper()
		if err != nil {
			return err
		}
		indexer, err := blindindex.New(pepper)
		if err != nil {
			return err
		}
		auditRecorder, err = audit.NewIndexingRecorder(auditRecorder, db.New(pool), indexer, logger)
		if err != nil {
			return err
		}
	}
	adminDeps, err := buildAdminServices(cfg.Admin, cfg.Environment, pool, redisClient)
	if err != nil {
		return err
	}

	// The GDPR privacy service reuses the WebAuthn database pool, the session
	// manager and refresh-token store (both revoked at soft-delete), the two factor
	// verifiers (as the reclaim ceremony's factors), and Redis for rate limiting and
	// passcode replay protection. It additionally requires a notifier that can
	// actually deliver the reclaim token; outside development, when none is
	// configured it returns nil so the deletion routes stay unmounted.
	privacyService, err := buildPrivacyService(
		cfg.Environment, pool, redisClient, sessionManager, refreshTokenStore,
		webauthnService, mfaService, auditRecorder, logger)
	if err != nil {
		return err
	}

	var grpcReady func(context.Context) error
	if cfg.GRPC.Enabled {
		validator, err := token.NewAccessValidator(token.AccessValidatorConfig{Issuer: oidcCfg.Issuer, Keys: keyManager,
			Clients: clientRegistry, Grants: refreshTokenStore, Sessions: sessionManager, Accounts: accounts})
		if err != nil {
			return err
		}
		grpcServer, err = buildPrivateGRPC(context.Background(), cfg.GRPC, grpcDependencies{Validator: validator,
			Queries: db.New(pool), DPoP: dpopValidator, Recorder: auditRecorder, Redis: redisClient,
			DatabaseReady: pool.Ping, AllowHTTP: cfg.Environment == "development"}, logger, nil)
		if err != nil {
			return err
		}
		grpcReady = grpcServer.Ready
	}

	srv := server.New(cfg, logger, server.Deps{
		AdminActions: adminDeps.AdminActions,
		AdminReady:   adminDeps.AdminReady,
		AdminRevoke: func(ctx context.Context, userID string) error {
			return errors.Join(sessionManager.RevokeAllForUser(ctx, userID), refreshTokenStore.RevokeAllForUser(ctx, userID))
		},
		GRPCReady:      grpcReady,
		AdminStore:     adminDeps.AdminStore,
		LedgerProofDB:  pool,
		RBAC:           adminDeps.RBAC,
		LegalHold:      adminDeps.LegalHold,
		LegalWorkflow:  adminDeps.LegalWorkflow,
		LegalReports:   adminDeps.LegalReports,
		AdminLimiter:   adminDeps.AdminLimiter,
		OIDC:           oidcCfg,
		Keys:           keyManager,
		Clients:        clientRegistry,
		TokenService:   tokenService,
		DPoPValidator:  dpopValidator,
		SessionManager: sessionManager,
		WebAuthn:       webauthnService,
		MFA:            mfaService,
		SMSOTP:         smsotpService,
		Recovery:       recoveryService,
		RecoveryFlow:   recoveryFlow,
		StepUp:         stepupService,
		Privacy:        privacyService,
		AuditRecorder:  auditRecorder,
	})

	// Listen for OS termination signals to trigger graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the server in a goroutine so we can wait on the signal context.
	serverErr := make(chan error, 2)
	go func() {
		serverErr <- srv.Start()
	}()
	if grpcServer != nil {
		go func() { serverErr <- grpcServer.Start() }()
	}

	var serveErr error
	select {
	case err := <-serverErr:
		serveErr = err
	case <-ctx.Done():
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return errors.Join(serveErr, shutdownServers(shutdownCtx, srv, grpcServer))
}

func shutdownServers(ctx context.Context, httpServer *server.Server, grpcServer *privateGRPC) error {
	results := make(chan error, 2)
	go func() {
		err := httpServer.Shutdown(ctx)
		if err != nil {
			err = errors.Join(err, httpServer.Close())
		}
		results <- err
	}()
	count := 1
	if grpcServer != nil {
		count++
		go func() { results <- grpcServer.Shutdown(ctx) }()
	}
	var result error
	for range count {
		result = errors.Join(result, <-results)
	}
	return result
}

// drainAuditRecorder flushes the audit transport during shutdown.
//
// It builds its own deadline rather than reusing the HTTP shutdown context: that one
// may already be spent by a slow in-flight request, and the buffered events must
// still get a full, predictable window to reach the stream. A failure here is
// returned, not swallowed — the undrained remainder is precisely the set of audit
// events this process lost.
func drainAuditRecorder(closeAudit func(context.Context) error, timeout time.Duration, logger *slog.Logger) error {
	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := closeAudit(drainCtx); err != nil {
		logger.Error("audit transport did not drain cleanly; some audit events were not published",
			slog.String("marker", audit.AuditTransportFailureMarker),
			slog.String("error", err.Error()))
		return err
	}
	return nil
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

// buildTokenService assembles shared code/grant authority and the RFC 7523 private_key_jwt client
// authenticator for the client_credentials grant. The authenticator's expected
// audience is the fully-qualified token endpoint URL so an assertion minted for
// a different endpoint is rejected (audience-confusion defence).
//
// The refresh-token store is returned alongside the service because the GDPR
// deletion flow must revoke every refresh-token family for a subject
// (docs/architecture.md "The 30-Day Recovery Window"). Constructing it here and
// handing out the same instance is what keeps that revocation effective; building a
// second store for the privacy service would revoke tokens nobody holds.
func buildTokenService(
	oidcCfg config.OIDCConfig,
	keyManager *keys.Manager,
	clientRegistry *clients.StaticRegistry,
	logger *slog.Logger,
	accounts session.AccountState,
	sessions *session.Manager,
	redisClient *redis.Client,
	revokeUser func(context.Context, string) error,
) (*token.Service, token.RefreshTokenStore, error) {
	tokenEndpoint := oidcCfg.Issuer + "/oauth2/token"
	authenticator, err := clientauth.New(clientRegistry, tokenEndpoint, clientauth.NewMemoryJTIGuard())
	if err != nil {
		return nil, nil, fmt.Errorf("main: build client authenticator: %w", err)
	}

	var codes token.AuthorizationCodeStore = token.NewMemoryCodeStore()
	var refreshTokens token.RefreshTokenStore = token.NewMemoryRefreshTokenStore()
	if redisClient != nil {
		codes, err = token.NewRedisCodeStore(redisClient)
		if err != nil {
			return nil, nil, err
		}
		refreshTokens, err = token.NewRedisRefreshTokenStore(redisClient)
		if err != nil {
			return nil, nil, err
		}
	}
	svc, err := token.NewService(
		token.Config{Issuer: oidcCfg.Issuer, AccountState: accounts, Sessions: sessions, RevokeUser: revokeUser},
		keyManager,
		clientRegistry,
		codes,
		refreshTokens,
		authenticator,
		nil,
		logger,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("main: build token service: %w", err)
	}
	return svc, refreshTokens, nil
}

// buildDPoPValidator shares replay and nonce authority across HTTP and gRPC.
// Memory stores are used only for development without Redis and without gRPC.
func buildDPoPValidator(redisClient *redis.Client) (*dpop.Validator, error) {
	var replay dpop.ReplayGuard = dpop.NewMemoryReplayGuard()
	var nonces dpop.NonceStore = dpop.NewMemoryNonceStore()
	var err error
	if redisClient != nil {
		replay, err = dpop.NewRedisReplayGuard(redisClient)
		if err != nil {
			return nil, err
		}
		nonces, err = dpop.NewRedisNonceStore(redisClient)
		if err != nil {
			return nil, err
		}
	}
	validator, err := dpop.NewValidator(replay, nonces)
	if err != nil {
		return nil, fmt.Errorf("main: build DPoP validator: %w", err)
	}
	return validator, nil
}

// buildSessionManager assembles the stateful browser-session lifecycle: the
// hardened __Host- cookie codec, shared Redis authority when configured, and the
// Manager that owns the absolute/idle lifetime policy. Configuration (cookie
// name/Secure and the two TTLs) is loaded from the environment; the
// __Host-/Secure invariant is enforced inside NewCookieCodec so a misconfigured
// dev override fails fast at startup.
func buildSessionManager(accounts session.AccountState, redisClient *redis.Client) (*session.Manager, error) {
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

	var store session.Store = session.NewMemoryStore()
	if redisClient != nil {
		store, err = session.NewRedisStore(redisClient)
		if err != nil {
			return nil, err
		}
	}
	manager, err := session.NewManager(store, codec, session.ManagerConfig{
		AccountState: accounts,
		AbsoluteTTL:  sc.AbsoluteTTL,
		IdleTTL:      sc.IdleTTL,
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
		AccountState:     session.NewDBAccountState(pool),
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

// redisConnectTimeout bounds the startup connectivity probe against Redis so an
// unreachable cache fails the boot quickly instead of hanging the process.
const redisConnectTimeout = 5 * time.Second

// buildRedisClient opens the Redis connection backing the SMS OTP rate limiter
// and code store. It parses REDIS_URL (redis://... — the same variable used by
// docker-compose.dev.yml) and probes connectivity once at startup.
//
// Following the WebAuthn precedent, a missing REDIS_URL is tolerated in
// development: the client is skipped (nil return), which leaves the phone
// routes unmounted so the rest of the API still boots for local work. Outside
// development Redis is mandatory, so a missing REDIS_URL is a startup error.
func buildRedisClient(environment string, logger *slog.Logger) (*redis.Client, error) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		if environment != "development" {
			return nil, fmt.Errorf("main: REDIS_URL is required in %q environment", environment)
		}
		logger.Warn("no REDIS_URL configured; SMS OTP phone routes are disabled")
		return nil, nil
	}

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("main: parse REDIS_URL: %w", err)
	}
	// These stores consume single-use credentials. Do not transparently replay
	// an operation after an ambiguous response, or ignore a caller's deadline.
	opts.ContextTimeoutEnabled = true
	opts.MaxRetries = -1
	opts.DialTimeout = 2 * time.Second
	opts.ReadTimeout = time.Second
	opts.WriteTimeout = time.Second
	opts.PoolTimeout = time.Second
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), redisConnectTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("main: ping redis: %w", err)
	}
	return client, nil
}

// buildSMSOTPService assembles the SMS OTP phone-verification service (Task
// 4.5). It needs both a database (to persist the verified, envelope-encrypted
// phone and its blind index) and Redis (for the independent-dimension sliding
// window rate limits and the pending-code / lockout store), plus the crypto
// module secrets.
//
// When either backing store is absent — which only happens in development,
// since buildWebAuthnService/buildRedisClient already make them mandatory
// elsewhere — the service is skipped (nil return) and its routes are left
// unmounted, matching the WebAuthn precedent. In development the log-only
// sender is used so no real SMS gateway credential is required.
func buildSMSOTPService(environment string, pool *pgxpool.Pool, redisClient *redis.Client, logger *slog.Logger) (*smsotp.Service, error) {
	if pool == nil || redisClient == nil {
		logger.Warn("SMS OTP service disabled (requires both DATABASE_URL and REDIS_URL)")
		return nil, nil
	}

	smsCfg, err := config.LoadSMS(environment)
	if err != nil {
		return nil, err
	}

	if os.Getenv(config.EnvBlindIndexPepper) == "" {
		logger.Warn("SMS OTP service disabled (requires ENVELOPE_BLIND_INDEX_PEPPER)")
		return nil, nil
	}

	cryptoCfg, err := config.LoadCrypto()
	if err != nil {
		return nil, err
	}

	provider, err := kms.NewMockProvider(cryptoCfg.MasterKEK, cryptoCfg.MasterKEKVersion)
	if err != nil {
		return nil, fmt.Errorf("main: build KMS provider: %w", err)
	}
	encryptor, err := envelope.New(provider)
	if err != nil {
		return nil, fmt.Errorf("main: build envelope encryptor: %w", err)
	}
	indexer, err := blindindex.New(cryptoCfg.BlindIndexPepper)
	if err != nil {
		return nil, fmt.Errorf("main: build blind indexer: %w", err)
	}

	limiter, err := ratelimit.NewRedisLimiter(redisClient)
	if err != nil {
		return nil, fmt.Errorf("main: build rate limiter: %w", err)
	}
	otpStore, err := smsotp.NewRedisOTPStore(redisClient)
	if err != nil {
		return nil, fmt.Errorf("main: build OTP store: %w", err)
	}

	// Development uses the log-only sender (no real gateway/toll cost). A real
	// gateway client is wired here in production once the provider is chosen.
	sender := smsotp.NewLogSender(logger)

	svc, err := smsotp.New(smsotp.Config{
		CodeTTL:           smsCfg.CodeTTL,
		MaxAttempts:       smsCfg.MaxAttempts,
		LockoutTTL:        smsCfg.LockoutTTL,
		PerPhonePerMinute: smsCfg.PerPhonePerMinute,
		PerPhonePerHour:   smsCfg.PerPhonePerHour,
		PerSubnetPerHour:  smsCfg.PerSubnetPerHour,
		HashPepper:        smsCfg.HashPepper,
	}, db.New(pool), encryptor, indexer, limiter, otpStore, sender)
	if err != nil {
		return nil, fmt.Errorf("main: build SMS OTP service: %w", err)
	}

	logger.Info("sms otp service configured",
		slog.Int("per_phone_per_minute", smsCfg.PerPhonePerMinute),
		slog.Int("per_phone_per_hour", smsCfg.PerPhonePerHour),
		slog.Int("per_subnet_per_hour", smsCfg.PerSubnetPerHour),
		slog.Int("max_attempts", smsCfg.MaxAttempts),
	)
	return svc, nil
}

// buildMFAService assembles the TOTP MFA service (Task 4.4). It reuses the
// WebAuthn database pool for the user store and the crypto module for
// envelope-encrypting the stored TOTP secret.
//
// When no database is configured — development only, since buildWebAuthnService
// already makes it mandatory elsewhere — the service is skipped (nil return)
// and its routes are left unmounted, matching the WebAuthn precedent.
func buildMFAService(pool *pgxpool.Pool, logger *slog.Logger) (*mfa.Service, error) {
	if pool == nil {
		logger.Warn("MFA service disabled (requires DATABASE_URL)")
		return nil, nil
	}

	cryptoCfg, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return nil, err
	}

	provider, err := kms.NewMockProvider(cryptoCfg.MasterKEK, cryptoCfg.MasterKEKVersion)
	if err != nil {
		return nil, fmt.Errorf("main: build KMS provider: %w", err)
	}
	encryptor, err := envelope.New(provider)
	if err != nil {
		return nil, fmt.Errorf("main: build envelope encryptor: %w", err)
	}

	svc, err := mfa.New(mfa.Config{}, db.New(pool), encryptor, mfa.WithTransacter(pool))
	if err != nil {
		return nil, fmt.Errorf("main: build MFA service: %w", err)
	}

	logger.Info("totp mfa service configured")
	return svc, nil
}

// buildRecoveryService assembles the recovery (backup) code service (Task 4.6).
// It reuses the WebAuthn database pool for the code store and, when Redis is
// configured, the shared sliding-window limiter to throttle generate/verify by
// account and subnet. The optional hash pepper is injected from the
// environment/KMS; when unset the service falls back to plain SHA-256.
//
// When no database is configured — development only, since buildWebAuthnService
// already makes it mandatory elsewhere — the service is skipped (nil return)
// and its routes are left unmounted, matching the WebAuthn precedent.
func buildRecoveryService(environment string, pool *pgxpool.Pool, redisClient *redis.Client, logger *slog.Logger) (*recovery.Service, *recovery.FlowService, error) {
	if pool == nil {
		logger.Warn("recovery-code service disabled (requires DATABASE_URL)")
		return nil, nil, nil
	}

	rc, err := config.LoadRecovery()
	if err != nil {
		return nil, nil, err
	}

	opts := []recovery.Option{recovery.WithTransacter(pool)}

	// The recovery limiter is best-effort hardening: when Redis is present it
	// throttles brute force against the verify endpoint and abuse of generate,
	// but its absence (development) must not disable the codes themselves.
	if redisClient != nil {
		limiter, err := ratelimit.NewRedisLimiter(redisClient)
		if err != nil {
			return nil, nil, fmt.Errorf("main: build rate limiter: %w", err)
		}
		opts = append(opts, recovery.WithRateLimiter(limiter))
	}

	svc, err := recovery.New(recovery.Config{
		Count:             rc.Count,
		EntropyBits:       rc.EntropyBits,
		LowThreshold:      rc.LowThreshold,
		HashPepper:        rc.HashPepper,
		PerAccountPerHour: rc.PerAccountPerHour,
		PerSubnetPerHour:  rc.PerSubnetPerHour,
	}, db.New(pool), opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("main: build recovery service: %w", err)
	}

	var transactionStore recovery.TransactionStore
	if redisClient != nil {
		transactionStore, err = recovery.NewRedisTransactionStore(redisClient)
		if err != nil {
			return nil, nil, fmt.Errorf("main: build recovery transaction store: %w", err)
		}
	} else {
		transactionStore = recovery.NewMemoryTransactionStore()
		logger.Warn("recovery transactions use development-only in-memory storage")
	}
	webAuthnCfg, err := config.LoadWebAuthn(environment)
	if err != nil {
		return nil, nil, err
	}
	flow, err := recovery.NewFlowService(svc, db.New(pool), transactionStore, webAuthnCfg.NamedLoginFloor)
	if err != nil {
		return nil, nil, fmt.Errorf("main: build recovery flow: %w", err)
	}

	logger.Info("recovery code service configured",
		slog.Int("count", rc.Count),
		slog.Int("entropy_bits", rc.EntropyBits),
		slog.Int("low_threshold", rc.LowThreshold),
		slog.Bool("rate_limited", redisClient != nil),
		slog.Bool("peppered", len(rc.HashPepper) > 0),
	)
	return svc, flow, nil
}

// buildStepUpService assembles the Step-up Authentication service (Task 4.7). It
// reuses the WebAuthn database pool for the user lookup, the OIDC keystore to
// sign and verify grants (so they follow the same active/next/previous rotation
// as access and ID tokens), and the WebAuthn and TOTP services as the two factor
// verifiers.
//
// When no database is configured — development only, since buildWebAuthnService
// already makes it mandatory elsewhere — the service is skipped (nil return).
// That leaves not only the step-up routes unmounted but every step-up-gated route
// as well: an endpoint documented as requiring X-Step-Up-Auth must never become
// reachable without it, so an absent service fails closed. See server.Deps.StepUp.
//
// Production replay claims are stored cluster-wide in Redis as HMAC-derived
// opaque keys. The in-memory guard is retained only for explicit development
// when no replay HMAC key or Redis connection is configured.
//
// Unlike the recovery-code limiter, throttling here is not merely best-effort
// hardening: the per-minute account window is what keeps a 6-digit TOTP passcode
// out of brute-force reach. Redis is already mandatory outside development (see
// buildRedisClient), so the limiter is always present in production.
func buildStepUpService(
	environment string,
	pool *pgxpool.Pool,
	redisClient *redis.Client,
	keyManager *keys.Manager,
	oidcCfg config.OIDCConfig,
	webauthnSvc *webauthn.Service,
	mfaSvc *mfa.Service,
	logger *slog.Logger,
) (*stepup.Service, error) {
	if pool == nil {
		logger.Warn("step-up service disabled (requires DATABASE_URL); step-up gated routes will not be mounted")
		return nil, nil
	}

	sc, err := config.LoadStepUp(environment)
	if err != nil {
		return nil, err
	}

	// Only pass a verifier that actually exists; stepup.New requires at least
	// one, so a process with neither fails at startup rather than mounting gated
	// routes no caller could ever satisfy.
	var passkeys stepup.PasskeyVerifier
	if webauthnSvc != nil {
		passkeys = webauthnSvc
	}
	var totp stepup.TOTPVerifier
	if mfaSvc != nil {
		totp = mfaSvc
	}

	opts := []stepup.Option{}
	var replayGuard stepup.ReplayGuard
	distributedReplay := redisClient != nil && len(sc.ReplayHMACKey) > 0
	if redisClient != nil {
		limiter, err := ratelimit.NewRedisLimiter(redisClient)
		if err != nil {
			return nil, fmt.Errorf("main: build rate limiter: %w", err)
		}
		opts = append(opts, stepup.WithRateLimiter(limiter))
	}
	if distributedReplay {
		var err error
		replayGuard, err = stepup.NewRedisReplayGuard(redisClient, sc.ReplayHMACKey)
		if err != nil {
			return nil, fmt.Errorf("main: build distributed replay guard: %w", err)
		}
	} else {
		if redisClient == nil {
			logger.Warn("step-up verification is not rate limited (requires REDIS_URL)")
		}
		replayGuard = stepup.NewMemoryReplayGuard()
		logger.Warn("step-up replay protection uses development-only in-memory storage")
	}

	svc, err := stepup.New(stepup.Config{
		AccountState:        session.NewDBAccountState(pool),
		Issuer:              oidcCfg.Issuer,
		TokenTTL:            sc.TokenTTL,
		PerAccountPerMinute: sc.PerAccountPerMinute,
		PerAccountPerHour:   sc.PerAccountPerHour,
		PerSubnetPerHour:    sc.PerSubnetPerHour,
	}, keyManager, db.New(pool), passkeys, totp, replayGuard, opts...)
	if err != nil {
		return nil, fmt.Errorf("main: build step-up service: %w", err)
	}

	logger.Info("step-up service configured",
		slog.Duration("token_ttl", sc.TokenTTL),
		slog.String("acr", stepup.ACRStepUp),
		slog.Bool("webauthn_factor", passkeys != nil),
		slog.Bool("totp_factor", totp != nil),
		slog.Bool("rate_limited", redisClient != nil),
		slog.Bool("distributed_replay", distributedReplay),
	)
	return svc, nil
}

// buildPrivacyService assembles the GDPR "Right to be Forgotten" service (Task
// 5.1). It reuses the WebAuthn database pool, the session manager and the
// refresh-token store (both revoked synchronously at soft-delete), the WebAuthn and
// TOTP services as the reclaim ceremony's two factors, and Redis for the rate limits
// and reclaim-passcode replay guard.
//
// Notifier selection is the fail-closed decision this function exists to make. A
// deletion whose reclaim token cannot be delivered has no 30-day recovery window at
// all, so:
//
//   - development gets the log-only notifier, which keeps the flow runnable locally
//     with no mail provider;
//   - any other environment with no real notifier gets a warning and a nil service,
//     which leaves DELETE /api/v1/users/me and the reclaim endpoints unmounted (404).
//
// It is deliberately not a boot failure. Refusing to start would take down login,
// token issuance, and every other endpoint over a feature that is not yet
// deliverable; withholding just the deletion routes is the proportionate response,
// and their absence is visible in the startup log and in the route table.
//
// A missing database has the same effect for the same reason as everywhere else in
// this file (development only, since buildWebAuthnService already makes it mandatory
// elsewhere).
func buildPrivacyService(
	environment string,
	pool *pgxpool.Pool,
	redisClient *redis.Client,
	sessionManager *session.Manager,
	refreshTokens token.RefreshTokenStore,
	webauthnSvc *webauthn.Service,
	mfaSvc *mfa.Service,
	auditRecorder audit.Recorder,
	logger *slog.Logger,
) (*privacy.Service, error) {
	if pool == nil {
		logger.Warn("privacy service disabled (requires DATABASE_URL); deletion routes not mounted")
		return nil, nil
	}

	pc, err := config.LoadPrivacy(environment)
	if err != nil {
		return nil, err
	}

	// There is no production email notifier yet (see internal/privacy's known
	// follow-ups). Until one is wired here, only development can mount the routes.
	var notifier privacy.Notifier
	if environment == "development" {
		notifier = privacy.NewLogNotifier(logger)
		logger.Warn("privacy deletion notices use the development-only log notifier")
	} else {
		logger.Warn("privacy: no production notifier configured; deletion routes not mounted")
		return nil, nil
	}

	opts := []privacy.Option{
		privacy.WithTransacter(pool),
		privacy.WithLogger(logger),
	}
	if sessionManager != nil {
		opts = append(opts, privacy.WithSessionRevoker(sessionManager))
	}
	if refreshTokens != nil {
		opts = append(opts, privacy.WithTokenRevoker(refreshTokens))
	}
	if webauthnSvc != nil {
		opts = append(opts, privacy.WithPasskeyReclaimer(webauthnSvc))
	}
	if mfaSvc != nil {
		opts = append(opts, privacy.WithTOTPReclaimer(mfaSvc))
	}

	if redisClient != nil {
		limiter, err := ratelimit.NewRedisLimiter(redisClient)
		if err != nil {
			return nil, fmt.Errorf("main: build rate limiter: %w", err)
		}
		opts = append(opts, privacy.WithRateLimiter(limiter))
	}

	// The reclaim passcode reuses the step-up replay guard so a code cannot be
	// replayed across its ±1-step acceptance window. Distributed claims need both
	// Redis and the shared HMAC key; without them the in-memory guard is
	// process-local, which is only acceptable in development.
	sc, err := config.LoadStepUp(environment)
	if err != nil {
		return nil, err
	}
	if redisClient != nil && len(sc.ReplayHMACKey) > 0 {
		guard, err := stepup.NewRedisReplayGuard(redisClient, sc.ReplayHMACKey)
		if err != nil {
			return nil, fmt.Errorf("main: build privacy replay guard: %w", err)
		}
		opts = append(opts, privacy.WithReplayGuard(guard))
	} else {
		opts = append(opts, privacy.WithReplayGuard(stepup.NewMemoryReplayGuard()))
		logger.Warn("privacy reclaim replay protection uses development-only in-memory storage")
	}

	// The backup email is envelope-encrypted at rest, so a decryptor is required to
	// notify the second mailbox — which is what protects a user whose primary
	// mailbox was taken over as part of the takeover that triggered the deletion.
	cryptoCfg, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return nil, err
	}
	provider, err := kms.NewMockProvider(cryptoCfg.MasterKEK, cryptoCfg.MasterKEKVersion)
	if err != nil {
		return nil, fmt.Errorf("main: build KMS provider: %w", err)
	}
	encryptor, err := envelope.New(provider)
	if err != nil {
		return nil, fmt.Errorf("main: build envelope encryptor: %w", err)
	}
	opts = append(opts, privacy.WithDecryptor(encryptor))

	svc, err := privacy.New(privacy.Config{
		GracePeriod:              pc.GracePeriod,
		ReclaimMaxAttempts:       pc.ReclaimMaxAttempts,
		ReclaimPerAccountPerHour: pc.ReclaimPerAccountPerHour,
		ReclaimPerSubnetPerHour:  pc.ReclaimPerSubnetPerHour,
		DeletePerAccountPerDay:   pc.DeletePerAccountPerDay,
		DeleteResendCooldown:     pc.DeleteResendCooldown,
	}, db.New(pool), notifier, auditRecorder, opts...)
	if err != nil {
		return nil, fmt.Errorf("main: build privacy service: %w", err)
	}

	logger.Info("privacy configured",
		slog.Duration("grace_period", pc.GracePeriod),
		slog.Duration("resend_cooldown", pc.DeleteResendCooldown),
		slog.Int("reclaim_max_attempts", pc.ReclaimMaxAttempts),
		slog.Bool("webauthn_factor", webauthnSvc != nil),
		slog.Bool("totp_factor", mfaSvc != nil),
		slog.Bool("rate_limited", redisClient != nil),
		slog.Bool("development_notifier", notifier.IsDevelopmentOnly()),
	)
	return svc, nil
}

// buildAuditRecorder assembles the audit transport shared by the HTTP handlers and
// the privacy service (Task 5.2).
//
// It never declares JetStream topology. internal/natsjs documents why:
// CreateOrUpdateStream is authoritative, so an API replica rolled out with a stale
// value would silently rewrite the stream's limits underneath the signing worker.
// The signer owns the definition; every API instance is only a publisher. The
// visible consequence is that publishing before the signer has ever run finds no
// stream and takes the publisher's log-fallback path, which is loud and recoverable
// rather than silent.
//
// Without NATS_URL it degrades to the Task 5.1 LogRecorder. LoadAudit already
// refuses that outside development, so this fallback cannot reach production: there,
// a missing audit transport is a startup failure, not a downgrade to unchained logs.
//
// The returned closer is safe to call even when nothing was started.
func buildAuditRecorder(
	ctx context.Context,
	environment string,
	logger *slog.Logger,
) (audit.Recorder, func(context.Context) error, error) {
	ac, err := config.LoadAudit(environment)
	if err != nil {
		return nil, func(context.Context) error { return nil }, err
	}

	if !ac.HasNATS() {
		logger.Warn("audit pipeline disabled (requires NATS_URL); events are logged unchained and are not written to either ledger",
			slog.String("environment", environment))
		return audit.NewLogRecorder(logger), func(context.Context) error { return nil }, nil
	}

	nc, js, err := natsjs.Connect(ctx, ac.NATSURL, "identity-api", logger)
	if err != nil {
		return nil, func(context.Context) error { return nil }, err
	}

	recorder, err := audit.NewJetStreamRecorder(js, ac.Subject, ac.PublishBuffer, logger)
	if err != nil {
		nc.Close()
		return nil, func(context.Context) error { return nil }, fmt.Errorf("main: build audit recorder: %w", err)
	}

	logger.Info("audit pipeline configured",
		slog.String("subject", ac.Subject),
		slog.Int("publish_buffer", ac.PublishBuffer),
	)

	closer := func(shutdownCtx context.Context) error {
		// Order matters: drain the recorder's buffer and wait for its acks before the
		// connection goes away, or the tail of the buffer is published into a closed
		// connection and lands in the fallback log instead of the ledger.
		closeErr := recorder.Close(shutdownCtx)

		// Drain rather than Close: it flushes what the client still holds and waits
		// for the server to process it. A drain failure is reported but does not mask
		// the recorder's own error, which is the one that says whether audit events
		// were lost.
		if drainErr := nc.Drain(); drainErr != nil {
			if closeErr != nil {
				return closeErr
			}
			return fmt.Errorf("main: drain NATS connection: %w", drainErr)
		}
		return closeErr
	}
	return recorder, closer, nil
}
