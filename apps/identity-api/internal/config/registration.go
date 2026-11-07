package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

// Registration environment keys configure admission and the dedicated cleanup worker.
const (
	EnvRegistrationEnabled            = "REGISTRATION_ENABLED"
	EnvRegistrationPendingCapacity    = "REGISTRATION_PENDING_CAPACITY"
	EnvRegistrationGlobalDailyLimit   = "REGISTRATION_GLOBAL_DAILY_LIMIT"
	EnvRegistrationEmailHourlyLimit   = "REGISTRATION_EMAIL_HOURLY_LIMIT"
	EnvRegistrationCleanupDatabaseURL = "REGISTRATION_CLEANUP_DATABASE_URL"
	EnvRegistrationCleanupBatchSize   = "REGISTRATION_CLEANUP_BATCH_SIZE"
)

// RegistrationConfig contains finite admission policy and an independent signup
// relay. Composition must also verify schema/keys/Redis/SMTPUTF8 before exposure.
// Provider provenance and cleanup supervision remain external activation gates.
type RegistrationConfig struct {
	Enabled          bool
	PendingCapacity  int32
	GlobalDailyLimit int
	EmailHourlyLimit int
	SMTP             smtptransport.Config
	PublicOrigin     string
}

// LoadRegistration validates explicit mode and prerequisites for enabled signup.
func LoadRegistration(environment string) (RegistrationConfig, error) {
	if err := ValidateEnvironment(environment); err != nil {
		return RegistrationConfig{}, err
	}
	cfg := RegistrationConfig{}
	raw := os.Getenv(EnvRegistrationEnabled)
	if raw != "" && raw != "true" && raw != "false" {
		return cfg, fmt.Errorf("config: %s must be true or false", EnvRegistrationEnabled)
	}
	cfg.Enabled = raw == "true"
	if !cfg.Enabled {
		return cfg, nil
	}
	capacity, err := registrationLimit(EnvRegistrationPendingCapacity, 10000)
	if err != nil {
		return RegistrationConfig{}, err
	}
	cfg.PendingCapacity = int32(capacity) // #nosec G115 -- registrationLimit guarantees 1..10000.
	if cfg.GlobalDailyLimit, err = registrationLimit(EnvRegistrationGlobalDailyLimit, 100000); err != nil {
		return RegistrationConfig{}, err
	}
	if cfg.EmailHourlyLimit, err = registrationLimit(EnvRegistrationEmailHourlyLimit, 10); err != nil {
		return RegistrationConfig{}, err
	}
	sms, err := LoadSMS(environment)
	if err != nil || !sms.Enabled || sms.Provider != "smsir" || sms.KeyMode != "live" || sms.GlobalPerDay < 1 || sms.MaxPendingSignup < 1 {
		return RegistrationConfig{}, fmt.Errorf("config: registration requires live SMS and finite shared SMS budgets")
	}
	if sms.MaxPendingSignup != capacity {
		return RegistrationConfig{}, fmt.Errorf("config: registration and SMS pending capacity must match")
	}
	if strings.TrimSpace(os.Getenv("DATABASE_URL")) == "" || strings.TrimSpace(os.Getenv("REDIS_URL")) == "" {
		return RegistrationConfig{}, fmt.Errorf("config: registration requires database and Redis authority")
	}
	cfg.SMTP = smtptransport.Config{
		Host: os.Getenv("REGISTRATION_SMTP_HOST"), TLSMode: os.Getenv("REGISTRATION_SMTP_TLS_MODE"),
		Username: os.Getenv("REGISTRATION_SMTP_USERNAME"), Password: os.Getenv("REGISTRATION_SMTP_PASSWORD"),
		From: os.Getenv("REGISTRATION_SMTP_FROM"), CABundlePath: os.Getenv("REGISTRATION_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second,
	}
	port, err := strconv.Atoi(os.Getenv("REGISTRATION_SMTP_PORT"))
	if err != nil {
		return RegistrationConfig{}, fmt.Errorf("config: registration SMTP port required")
	}
	cfg.SMTP.Port = port
	if raw := os.Getenv("REGISTRATION_SMTP_TIMEOUT"); raw != "" {
		cfg.SMTP.Timeout, err = time.ParseDuration(raw)
		if err != nil || cfg.SMTP.Timeout < time.Millisecond || cfg.SMTP.Timeout > 5*time.Second {
			return RegistrationConfig{}, fmt.Errorf("config: registration SMTP timeout outside 1ms..5s")
		}
	}
	if cfg.SMTP.Validate() != nil {
		return RegistrationConfig{}, fmt.Errorf("config: invalid registration TLS SMTP configuration")
	}
	cfg.PublicOrigin = os.Getenv("REGISTRATION_SMTP_PUBLIC_ORIGIN")
	canonical, err := canonicalPortalOrigin(cfg.PublicOrigin, environment)
	portal, portalErr := canonicalPortalOrigin(os.Getenv("PORTAL_ORIGIN"), environment)
	if err != nil || portalErr != nil || canonical != cfg.PublicOrigin || canonical != portal {
		return RegistrationConfig{}, fmt.Errorf("config: registration public origin must match portal origin")
	}
	return cfg, nil
}

func registrationLimit(key string, maximum int) (int, error) {
	raw := os.Getenv(key)
	n, err := strconv.Atoi(raw)
	if err != nil || raw == "" || raw != strconv.Itoa(n) || n < 1 || n > maximum {
		return 0, fmt.Errorf("config: %s requires an explicit integer in 1..%d", key, maximum)
	}
	return n, nil
}

// RegistrationCleanupConfig contains only the worker DSN and bounded batch policy.
type RegistrationCleanupConfig struct {
	DatabaseURL string
	BatchSize   int32
}

// LoadRegistrationCleanup reads only mode and the dedicated cleanup DSN/policy.
// It intentionally does not load API, enrollment, encryption or provider secrets.
func LoadRegistrationCleanup() (RegistrationCleanupConfig, error) {
	if _, err := LoadEnvironment(); err != nil {
		return RegistrationCleanupConfig{}, err
	}
	cfg := RegistrationCleanupConfig{DatabaseURL: os.Getenv(EnvRegistrationCleanupDatabaseURL), BatchSize: 100}
	if cfg.DatabaseURL == "" || strings.TrimSpace(cfg.DatabaseURL) != cfg.DatabaseURL || len(cfg.DatabaseURL) > 8192 {
		return RegistrationCleanupConfig{}, fmt.Errorf("config: dedicated registration cleanup database URL required")
	}
	if _, err := pgxpool.ParseConfig(cfg.DatabaseURL); err != nil {
		return RegistrationCleanupConfig{}, fmt.Errorf("config: invalid registration cleanup database URL")
	}
	if os.Getenv(EnvRegistrationCleanupBatchSize) != "" {
		size, err := registrationLimit(EnvRegistrationCleanupBatchSize, 500)
		if err != nil {
			return RegistrationCleanupConfig{}, err
		}
		cfg.BatchSize = int32(size) // #nosec G115 -- registrationLimit guarantees 1..500.
	}
	return cfg, nil
}
