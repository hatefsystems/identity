package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

func clearLifecycleEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"APP_ENV", "DATABASE_URL", EnvNATSURL, EnvLifecycleStreamName, EnvLifecycleStreamMaxBytes,
		EnvLifecycleStreamMaxAge, EnvLifecycleOutboxRetention, EnvLifecycleBatchSize,
		EnvLifecyclePublishTimeout, EnvLifecycleBatchTimeout, EnvLifecyclePollInterval,
		EnvLifecycleStartupTimeout, EnvLifecycleCleanupDatabaseURL, EnvLifecycleCleanupBatchSize,
	} {
		t.Setenv(key, "")
	}
	t.Setenv(EnvNATSURL, "nats://127.0.0.1:4222")
}

func TestLifecycleDevelopmentDefaultsRequireExplicitEnvironment(t *testing.T) {
	for _, environment := range []string{"", "production", "staging", "test", "Development", " development", "development "} {
		t.Run(environment, func(t *testing.T) {
			clearLifecycleEnvironment(t)
			t.Setenv("APP_ENV", environment)
			if _, err := LoadLifecycle(); err == nil {
				t.Fatal("implicit development retention accepted")
			}
			t.Setenv(EnvLifecycleStreamMaxAge, "168h")
			if _, err := LoadLifecycle(); err == nil {
				t.Fatal("missing outbox retention accepted")
			}
			t.Setenv(EnvLifecycleOutboxRetention, "24h")
			cfg, err := LoadLifecycle()
			if err != nil || cfg.StreamMaxAge != 168*time.Hour || cfg.OutboxRetention != 24*time.Hour {
				t.Fatalf("explicit finite policy rejected: %v", err)
			}
		})
	}
	clearLifecycleEnvironment(t)
	t.Setenv("APP_ENV", "development")
	cfg, err := LoadLifecycle()
	if err != nil || cfg.StreamName != "IDENTITY_USERS" || cfg.StreamMaxBytes != 128<<20 || cfg.StreamMaxAge != 168*time.Hour ||
		cfg.OutboxRetention != 168*time.Hour || cfg.Publisher != lifecycle.DefaultPublisherConfig() || cfg.StartupTimeout != 15*time.Second {
		t.Fatalf("development defaults changed: %+v %v", cfg, err)
	}
	// Provisioning has no need for a database, but a missing broker is never a log fallback.
	if cfg.DatabaseURL != "" {
		t.Fatal("unexpected database fallback")
	}
	t.Setenv(EnvNATSURL, " \t")
	if _, err := LoadLifecycle(); err == nil {
		t.Fatal("missing broker accepted even in development")
	}
}

func TestLifecycleConfigurationBoundsAndPrivacy(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvLifecycleStreamName, "identity.user.>"}, {EnvLifecycleStreamName, "private user@example.test"},
		{EnvLifecycleStreamMaxBytes, "0"}, {EnvLifecycleStreamMaxBytes, "16383"}, {EnvLifecycleStreamMaxBytes, "-1"},
		{EnvLifecycleStreamMaxBytes, "9223372036854775808"}, {EnvLifecycleStreamMaxBytes, "private-password"},
		{EnvLifecycleStreamMaxAge, "2m"}, {EnvLifecycleStreamMaxAge, "0"}, {EnvLifecycleStreamMaxAge, "-1h"},
		{EnvLifecycleStreamMaxAge, "999999999999999999999h"}, {EnvLifecycleStreamMaxAge, "infinite"},
		{EnvLifecycleOutboxRetention, "0"}, {EnvLifecycleOutboxRetention, "-1h"}, {EnvLifecycleOutboxRetention, "1ns"},
		{EnvLifecycleOutboxRetention, "private-password"}, {EnvLifecycleOutboxRetention, " "},
		{EnvLifecycleBatchSize, "0"}, {EnvLifecycleBatchSize, "201"}, {EnvLifecycleBatchSize, "-1"},
		{EnvLifecycleBatchSize, "2147483648"}, {EnvLifecycleBatchSize, "private-password"},
		{EnvLifecyclePublishTimeout, "0"}, {EnvLifecyclePublishTimeout, "1ns"}, {EnvLifecyclePublishTimeout, "61s"},
		{EnvLifecycleBatchTimeout, "1s"}, {EnvLifecycleBatchTimeout, "301s"}, {EnvLifecycleBatchTimeout, "private-password"},
		{EnvLifecyclePollInterval, "0"}, {EnvLifecyclePollInterval, "1ns"}, {EnvLifecyclePollInterval, "61s"},
		{EnvLifecycleStartupTimeout, "0"}, {EnvLifecycleStartupTimeout, "1ns"}, {EnvLifecycleStartupTimeout, "61s"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			clearLifecycleEnvironment(t)
			t.Setenv("APP_ENV", "development")
			t.Setenv(tc.key, tc.value)
			if _, err := LoadLifecycle(); err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "user@example.test") {
				t.Fatalf("invalid setting accepted or disclosed: %v", err)
			}
		})
	}
}

func TestLifecycleExplicitConfigurationAndLimits(t *testing.T) {
	clearLifecycleEnvironment(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("DATABASE_URL", " postgres://private:secret@localhost/db ")
	t.Setenv(EnvNATSURL, " nats://private:secret@localhost:4222 ")
	t.Setenv(EnvLifecycleStreamName, "USERS_v1-prod")
	t.Setenv(EnvLifecycleStreamMaxBytes, "16384")
	t.Setenv(EnvLifecycleStreamMaxAge, "2m0.000000001s")
	t.Setenv(EnvLifecycleOutboxRetention, "1us")
	t.Setenv(EnvLifecycleBatchSize, "200")
	t.Setenv(EnvLifecyclePublishTimeout, "1m")
	t.Setenv(EnvLifecycleBatchTimeout, "5m")
	t.Setenv(EnvLifecyclePollInterval, "1ms")
	t.Setenv(EnvLifecycleStartupTimeout, "1m")
	cfg, err := LoadLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StreamName != "USERS_v1-prod" || cfg.StreamMaxBytes != lifecycle.MaxMessageBytes || cfg.StreamMaxAge <= lifecycle.DuplicateWindow ||
		cfg.OutboxRetention != time.Microsecond || cfg.Publisher.BatchSize != 200 || cfg.Publisher.PublishTimeout != time.Minute ||
		cfg.Publisher.BatchTimeout != 5*time.Minute || cfg.Publisher.PollInterval != time.Millisecond || cfg.StartupTimeout != time.Minute {
		t.Fatal("explicit lifecycle settings not applied")
	}
	if cfg.DatabaseURL != strings.TrimSpace(os.Getenv("DATABASE_URL")) || cfg.NATSURL != strings.TrimSpace(os.Getenv(EnvNATSURL)) {
		t.Fatal("connection settings were not trimmed")
	}
}

func TestLifecycleProvisionLoadsOnlyBrokerPolicy(t *testing.T) {
	for _, retention := range []string{"", "private-invalid-retention"} {
		t.Run(retention, func(t *testing.T) {
			clearLifecycleEnvironment(t)
			t.Setenv("APP_ENV", "production")
			t.Setenv("DATABASE_URL", "invalid-private-database")
			t.Setenv(EnvLifecycleCleanupDatabaseURL, "invalid-private-cleanup-database")
			t.Setenv(EnvLifecycleOutboxRetention, retention)
			t.Setenv(EnvLifecycleBatchSize, "invalid-private-batch")
			t.Setenv(EnvLifecyclePublishTimeout, "invalid-private-timeout")
			if _, err := LoadLifecycleProvision(); err == nil {
				t.Fatal("provision silently chose production stream retention")
			}
			t.Setenv(EnvLifecycleStreamMaxAge, "48h")
			cfg, err := LoadLifecycleProvision()
			if err != nil || cfg.NATSURL == "" || cfg.StreamMaxAge != 48*time.Hour || cfg.StartupTimeout != 15*time.Second ||
				cfg.DatabaseURL != "" || cfg.OutboxRetention != 0 || cfg.Publisher != (lifecycle.PublisherConfig{}) {
				t.Fatalf("provision loaded or required unrelated credentials/policy: %v", err)
			}
			if _, err := LoadLifecycle(); err == nil {
				t.Fatal("publish stopped validating its own policy")
			}
		})
	}
}

func TestLifecycleCleanupIsSeparatelyCredentialedAndBrokerIndependent(t *testing.T) {
	clearLifecycleEnvironment(t)
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://publisher:secret@localhost/db")
	if _, err := LoadLifecycleCleanup(); err == nil {
		t.Fatal("cleanup fell back to publisher credentials")
	}
	t.Setenv(EnvLifecycleCleanupDatabaseURL, " postgres://maintenance:secret@localhost/db ")
	t.Setenv(EnvNATSURL, "invalid private credentials")
	t.Setenv(EnvLifecycleStreamName, "identity.user.>")
	t.Setenv(EnvLifecycleStreamMaxAge, "private-password")
	t.Setenv(EnvLifecycleStreamMaxBytes, "invalid")
	t.Setenv(EnvLifecyclePublishTimeout, "invalid")
	cfg, err := LoadLifecycleCleanup()
	if err != nil || cfg.DatabaseURL != strings.TrimSpace(os.Getenv(EnvLifecycleCleanupDatabaseURL)) || cfg.Retention != 168*time.Hour || cfg.BatchSize != 500 || cfg.StartupTimeout != 15*time.Second {
		t.Fatalf("cleanup loaded unrelated broker config or wrong defaults: %v", err)
	}
	t.Setenv("APP_ENV", "production")
	if _, err := LoadLifecycleCleanup(); err == nil {
		t.Fatal("cleanup silently chose a production retention")
	}
	t.Setenv(EnvLifecycleOutboxRetention, "72h")
	t.Setenv(EnvLifecycleCleanupBatchSize, "7")
	t.Setenv(EnvLifecycleStartupTimeout, "2s")
	cfg, err = LoadLifecycleCleanup()
	if err != nil || cfg.Retention != 72*time.Hour || cfg.BatchSize != 7 || cfg.StartupTimeout != 2*time.Second {
		t.Fatalf("explicit cleanup settings rejected: %v", err)
	}
}

func TestLifecycleCleanupRejectsInvalidBoundsWithoutValueDisclosure(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvLifecycleCleanupDatabaseURL, " "}, {EnvLifecycleCleanupBatchSize, "0"},
		{EnvLifecycleCleanupBatchSize, "501"}, {EnvLifecycleCleanupBatchSize, "-1"},
		{EnvLifecycleCleanupBatchSize, "private-password"}, {EnvLifecycleCleanupBatchSize, "9223372036854775808"},
		{EnvLifecycleOutboxRetention, "0"}, {EnvLifecycleOutboxRetention, "1ns"},
		{EnvLifecycleOutboxRetention, "private-password"}, {EnvLifecycleStartupTimeout, "61s"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			clearLifecycleEnvironment(t)
			t.Setenv("APP_ENV", "development")
			t.Setenv(EnvLifecycleCleanupDatabaseURL, "postgres://maintenance:private-password@localhost/db")
			t.Setenv(tc.key, tc.value)
			if _, err := LoadLifecycleCleanup(); err == nil || strings.Contains(err.Error(), "private-password") {
				t.Fatalf("cleanup bounds or privacy failure: %v", err)
			}
		})
	}
}
