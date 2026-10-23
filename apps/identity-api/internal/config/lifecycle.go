package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

// Environment variable names for lifecycle delivery and separate maintenance.
const (
	EnvLifecycleStreamName         = "LIFECYCLE_STREAM_NAME"
	EnvLifecycleStreamMaxBytes     = "LIFECYCLE_STREAM_MAX_BYTES"
	EnvLifecycleStreamMaxAge       = "LIFECYCLE_STREAM_MAX_AGE"
	EnvLifecycleOutboxRetention    = "LIFECYCLE_OUTBOX_RETENTION"
	EnvLifecycleBatchSize          = "LIFECYCLE_BATCH_SIZE"
	EnvLifecyclePublishTimeout     = "LIFECYCLE_PUBLISH_TIMEOUT"
	EnvLifecycleBatchTimeout       = "LIFECYCLE_BATCH_TIMEOUT"
	EnvLifecyclePollInterval       = "LIFECYCLE_POLL_INTERVAL"
	EnvLifecycleStartupTimeout     = "LIFECYCLE_STARTUP_TIMEOUT"
	EnvLifecycleCleanupDatabaseURL = "LIFECYCLE_CLEANUP_DATABASE_URL"
	EnvLifecycleCleanupBatchSize   = "LIFECYCLE_CLEANUP_BATCH_SIZE"
)

// LifecycleConfig holds worker resource bounds and explicit retention policy.
type LifecycleConfig struct {
	// Provisioning requires no database; the publish command requires this URL.
	DatabaseURL     string
	NATSURL         string
	StreamName      string
	StreamMaxBytes  int64
	StreamMaxAge    time.Duration
	OutboxRetention time.Duration
	Publisher       lifecycle.PublisherConfig
	StartupTimeout  time.Duration
}

// LifecycleCleanupConfig deliberately excludes broker and encryption credentials.
type LifecycleCleanupConfig struct {
	DatabaseURL    string
	Retention      time.Duration
	BatchSize      int32
	StartupTimeout time.Duration
}

// LoadLifecycleProvision loads only broker topology and startup policy. Database,
// publisher and outbox-retention fields remain unset and are not read.
func LoadLifecycleProvision() (LifecycleConfig, error) {
	cfg := LifecycleConfig{
		NATSURL:    strings.TrimSpace(os.Getenv(EnvNATSURL)),
		StreamName: getEnv(EnvLifecycleStreamName, "IDENTITY_USERS"),
	}
	if cfg.NATSURL == "" {
		return LifecycleConfig{}, errors.New("config: NATS_URL is required for lifecycle transport")
	}
	var err error
	if cfg.StreamMaxBytes, err = lifecycleInt(EnvLifecycleStreamMaxBytes, 128<<20, lifecycle.MaxMessageBytes, math.MaxInt64); err != nil {
		return LifecycleConfig{}, err
	}
	if cfg.StreamMaxAge, err = lifecycleDuration(EnvLifecycleStreamMaxAge, lifecycleRetentionDefault(), lifecycle.DuplicateWindow+1, math.MaxInt64); err != nil {
		return LifecycleConfig{}, err
	}
	if cfg.StartupTimeout, err = lifecycleDuration(EnvLifecycleStartupTimeout, 15*time.Second, time.Millisecond, time.Minute); err != nil {
		return LifecycleConfig{}, err
	}
	if err := (lifecycle.StreamOptions{Name: cfg.StreamName, MaxBytes: cfg.StreamMaxBytes, MaxAge: cfg.StreamMaxAge}).Validate(); err != nil {
		return LifecycleConfig{}, err
	}
	return cfg, nil
}

// LoadLifecycle never selects a log-only fallback, even in development.
func LoadLifecycle() (LifecycleConfig, error) {
	cfg, err := LoadLifecycleProvision()
	if err != nil {
		return LifecycleConfig{}, err
	}
	cfg.DatabaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	cfg.Publisher = lifecycle.DefaultPublisherConfig()
	if cfg.OutboxRetention, err = lifecycleDuration(EnvLifecycleOutboxRetention, lifecycleRetentionDefault(), time.Microsecond, math.MaxInt64); err != nil {
		return LifecycleConfig{}, err
	}
	batch, err := lifecycleInt(EnvLifecycleBatchSize, int64(cfg.Publisher.BatchSize), 1, 200)
	if err != nil || batch < 1 || batch > 200 {
		return LifecycleConfig{}, errors.New("config: LIFECYCLE_BATCH_SIZE must be in 1..200")
	}
	cfg.Publisher.BatchSize = int32(batch)
	for _, field := range []struct {
		key string
		dst *time.Duration
		max time.Duration
	}{
		{EnvLifecyclePublishTimeout, &cfg.Publisher.PublishTimeout, time.Minute},
		{EnvLifecycleBatchTimeout, &cfg.Publisher.BatchTimeout, 5 * time.Minute},
		{EnvLifecyclePollInterval, &cfg.Publisher.PollInterval, time.Minute},
	} {
		if *field.dst, err = lifecycleDuration(field.key, *field.dst, time.Millisecond, field.max); err != nil {
			return LifecycleConfig{}, err
		}
	}
	if err := cfg.Publisher.Validate(); err != nil {
		return LifecycleConfig{}, err
	}
	return cfg, nil
}

// LoadLifecycleCleanup never falls back to API/publisher credentials or loads
// unrelated broker configuration. A distinct environment key is not a substitute
// for the operator's least-privilege grants and hold-preservation policy.
func LoadLifecycleCleanup() (LifecycleCleanupConfig, error) {
	cfg := LifecycleCleanupConfig{DatabaseURL: strings.TrimSpace(os.Getenv(EnvLifecycleCleanupDatabaseURL))}
	if cfg.DatabaseURL == "" {
		return LifecycleCleanupConfig{}, errors.New("config: LIFECYCLE_CLEANUP_DATABASE_URL is required; publisher credentials are not a fallback")
	}
	var err error
	if cfg.Retention, err = lifecycleDuration(EnvLifecycleOutboxRetention, lifecycleRetentionDefault(), time.Microsecond, math.MaxInt64); err != nil {
		return LifecycleCleanupConfig{}, err
	}
	batch, err := lifecycleInt(EnvLifecycleCleanupBatchSize, 500, 1, 500)
	if err != nil || batch < 1 || batch > 500 {
		return LifecycleCleanupConfig{}, errors.New("config: LIFECYCLE_CLEANUP_BATCH_SIZE must be in 1..500")
	}
	cfg.BatchSize = int32(batch)
	if cfg.StartupTimeout, err = lifecycleDuration(EnvLifecycleStartupTimeout, 15*time.Second, time.Millisecond, time.Minute); err != nil {
		return LifecycleCleanupConfig{}, err
	}
	return cfg, nil
}

func lifecycleRetentionDefault() time.Duration {
	if os.Getenv("APP_ENV") == "development" {
		return 168 * time.Hour
	}
	return 0
}

// Configuration errors identify only the setting, never its raw value. Even a
// mistyped duration can contain credentials accidentally pasted by an operator.
func lifecycleDuration(key string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	value := fallback
	if raw := os.Getenv(key); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("config: %s requires a bounded duration", key)
		}
		value = parsed
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("config: %s must be explicitly set or within its permitted duration bounds", key)
	}
	return value, nil
}

func lifecycleInt(key string, fallback, minimum, maximum int64) (int64, error) {
	value := fallback
	if raw := os.Getenv(key); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("config: %s requires a bounded integer", key)
		}
		value = parsed
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("config: %s is outside permitted bounds", key)
	}
	return value, nil
}
