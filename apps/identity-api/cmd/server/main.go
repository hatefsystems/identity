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
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clientauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
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

	redisClient, err := buildRedisClient(cfg.Environment, logger)
	if err != nil {
		return err
	}
	if redisClient != nil {
		defer func() { _ = redisClient.Close() }()
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

	srv := server.New(cfg, logger, server.Deps{
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
