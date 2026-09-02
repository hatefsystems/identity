package config

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
)

// clearPrivacyEnv unsets every GDPR variable so a test starts from a known state
// regardless of the ambient environment (t.Setenv restores them on cleanup).
func clearPrivacyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EnvGDPRGracePeriod,
		EnvGDPRPurgeBatchSize,
		EnvGDPRPurgeDryRun,
		EnvGDPRReclaimMaxAttempts,
		EnvGDPRReclaimPerAccountPerHour,
		EnvGDPRReclaimPerSubnetPerHour,
		EnvGDPRDeletePerAccountPerDay,
		EnvGDPRDeleteResendCooldown,
	} {
		t.Setenv(k, "")
	}
}

func TestLoadPrivacyDefaults(t *testing.T) {
	clearPrivacyEnv(t)

	cfg, err := LoadPrivacy("production")
	if err != nil {
		t.Fatalf("LoadPrivacy: %v", err)
	}
	if cfg.GracePeriod != defaultGDPRGracePeriod {
		t.Errorf("GracePeriod = %v, want %v", cfg.GracePeriod, defaultGDPRGracePeriod)
	}
	// The documented window is 30 days; assert the arithmetic, not just the
	// constant, so a future edit to the literal is caught.
	if cfg.GracePeriod != 30*24*time.Hour {
		t.Errorf("GracePeriod = %v, want the documented 30 days", cfg.GracePeriod)
	}
	if cfg.PurgeBatchSize != defaultGDPRPurgeBatchSize {
		t.Errorf("PurgeBatchSize = %d, want %d", cfg.PurgeBatchSize, defaultGDPRPurgeBatchSize)
	}
	if cfg.PurgeDryRun {
		t.Error("PurgeDryRun = true, want false by default (a dry-run default would silently never purge)")
	}
	if cfg.ReclaimMaxAttempts != defaultGDPRReclaimMaxAttempts {
		t.Errorf("ReclaimMaxAttempts = %d, want %d", cfg.ReclaimMaxAttempts, defaultGDPRReclaimMaxAttempts)
	}
	if cfg.ReclaimPerAccountPerHour != defaultGDPRReclaimPerAccountPerHour {
		t.Errorf("ReclaimPerAccountPerHour = %d, want %d",
			cfg.ReclaimPerAccountPerHour, defaultGDPRReclaimPerAccountPerHour)
	}
	if cfg.ReclaimPerSubnetPerHour != defaultGDPRReclaimPerSubnetPerHour {
		t.Errorf("ReclaimPerSubnetPerHour = %d, want %d",
			cfg.ReclaimPerSubnetPerHour, defaultGDPRReclaimPerSubnetPerHour)
	}
	if cfg.DeletePerAccountPerDay != defaultGDPRDeletePerAccountPerDay {
		t.Errorf("DeletePerAccountPerDay = %d, want %d",
			cfg.DeletePerAccountPerDay, defaultGDPRDeletePerAccountPerDay)
	}
	if cfg.DeleteResendCooldown != defaultGDPRDeleteResendCooldown {
		t.Errorf("DeleteResendCooldown = %v, want %v",
			cfg.DeleteResendCooldown, defaultGDPRDeleteResendCooldown)
	}
}

func TestLoadPrivacyOverrides(t *testing.T) {
	clearPrivacyEnv(t)
	t.Setenv(EnvGDPRGracePeriod, "48h")
	t.Setenv(EnvGDPRPurgeBatchSize, "7")
	t.Setenv(EnvGDPRPurgeDryRun, "true")
	t.Setenv(EnvGDPRReclaimMaxAttempts, "3")
	t.Setenv(EnvGDPRReclaimPerAccountPerHour, "4")
	t.Setenv(EnvGDPRReclaimPerSubnetPerHour, "9")
	t.Setenv(EnvGDPRDeletePerAccountPerDay, "1")
	t.Setenv(EnvGDPRDeleteResendCooldown, "15m")

	cfg, err := LoadPrivacy("production")
	if err != nil {
		t.Fatalf("LoadPrivacy: %v", err)
	}
	if cfg.GracePeriod != 48*time.Hour {
		t.Errorf("GracePeriod = %v, want 48h", cfg.GracePeriod)
	}
	if cfg.PurgeBatchSize != 7 {
		t.Errorf("PurgeBatchSize = %d, want 7", cfg.PurgeBatchSize)
	}
	if !cfg.PurgeDryRun {
		t.Error("PurgeDryRun = false, want true")
	}
	if cfg.ReclaimMaxAttempts != 3 {
		t.Errorf("ReclaimMaxAttempts = %d, want 3", cfg.ReclaimMaxAttempts)
	}
	if cfg.ReclaimPerAccountPerHour != 4 {
		t.Errorf("ReclaimPerAccountPerHour = %d, want 4", cfg.ReclaimPerAccountPerHour)
	}
	if cfg.ReclaimPerSubnetPerHour != 9 {
		t.Errorf("ReclaimPerSubnetPerHour = %d, want 9", cfg.ReclaimPerSubnetPerHour)
	}
	if cfg.DeletePerAccountPerDay != 1 {
		t.Errorf("DeletePerAccountPerDay = %d, want 1", cfg.DeletePerAccountPerDay)
	}
	if cfg.DeleteResendCooldown != 15*time.Minute {
		t.Errorf("DeleteResendCooldown = %v, want 15m", cfg.DeleteResendCooldown)
	}
}

// TestLoadPrivacyGracePeriodFloor pins the boundary pair around the floor: exactly
// the minimum is accepted, one nanosecond below is rejected. A grace period shorter
// than a day is not a usable recovery window — the notification mail could
// plausibly not even be read in time — so it must fail at startup rather than
// silently ship a weaker user protection.
func TestLoadPrivacyGracePeriodFloor(t *testing.T) {
	t.Run("AtFloorAccepted", func(t *testing.T) {
		clearPrivacyEnv(t)
		t.Setenv(EnvGDPRGracePeriod, MinGDPRGracePeriod.String())

		cfg, err := LoadPrivacy("production")
		if err != nil {
			t.Fatalf("LoadPrivacy at the floor: %v", err)
		}
		if cfg.GracePeriod != MinGDPRGracePeriod {
			t.Errorf("GracePeriod = %v, want %v", cfg.GracePeriod, MinGDPRGracePeriod)
		}
	})

	t.Run("BelowFloorRejected", func(t *testing.T) {
		clearPrivacyEnv(t)
		t.Setenv(EnvGDPRGracePeriod, (MinGDPRGracePeriod - time.Nanosecond).String())

		if _, err := LoadPrivacy("production"); err == nil {
			t.Fatal("LoadPrivacy one nanosecond below the floor = nil error, want error")
		}
	})
}

func TestLoadPrivacyMalformedValues(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"GracePeriodNotADuration", EnvGDPRGracePeriod, "thirty-days"},
		{"GracePeriodZero", EnvGDPRGracePeriod, "0s"},
		{"GracePeriodNegative", EnvGDPRGracePeriod, "-1h"},
		{"BatchSizeNotAnInt", EnvGDPRPurgeBatchSize, "many"},
		{"BatchSizeZero", EnvGDPRPurgeBatchSize, "0"},
		{"BatchSizeNegative", EnvGDPRPurgeBatchSize, "-5"},
		{"DryRunNotABool", EnvGDPRPurgeDryRun, "yes"},
		{"MaxAttemptsZero", EnvGDPRReclaimMaxAttempts, "0"},
		{"ReclaimPerAccountNegative", EnvGDPRReclaimPerAccountPerHour, "-1"},
		{"ReclaimPerSubnetNotAnInt", EnvGDPRReclaimPerSubnetPerHour, "lots"},
		{"DeletePerDayZero", EnvGDPRDeletePerAccountPerDay, "0"},
		{"ResendCooldownZero", EnvGDPRDeleteResendCooldown, "0s"},
		{"ResendCooldownNotADuration", EnvGDPRDeleteResendCooldown, "soon"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearPrivacyEnv(t)
			t.Setenv(tc.key, tc.value)

			if _, err := LoadPrivacy("production"); err == nil {
				t.Fatalf("LoadPrivacy with %s=%q = nil error, want error", tc.key, tc.value)
			}
		})
	}
}

// TestLoadPrivacyConfigDrivesService is a guard against config/domain drift: the
// values LoadPrivacy produces must be accepted unchanged by both privacy.New and
// privacy.NewPurger, and must survive the round trip without a default silently
// overriding them.
//
// The stores are the real sqlc query set bound to a nil connection: nothing here
// executes a query, and using *db.Queries is what makes the check meaningful — it
// asserts that the generated type actually satisfies the interfaces the services
// declare, not just that some hand-written fake does.
func TestLoadPrivacyConfigDrivesService(t *testing.T) {
	clearPrivacyEnv(t)
	t.Setenv(EnvGDPRGracePeriod, "48h")
	t.Setenv(EnvGDPRPurgeBatchSize, "11")
	t.Setenv(EnvGDPRReclaimMaxAttempts, "2")

	cfg, err := LoadPrivacy("production")
	if err != nil {
		t.Fatalf("LoadPrivacy: %v", err)
	}

	queries := db.New(nil)
	recorder := audit.NewLogRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))

	svc, err := privacy.New(privacy.Config{
		GracePeriod:              cfg.GracePeriod,
		ReclaimMaxAttempts:       cfg.ReclaimMaxAttempts,
		ReclaimPerAccountPerHour: cfg.ReclaimPerAccountPerHour,
		ReclaimPerSubnetPerHour:  cfg.ReclaimPerSubnetPerHour,
		DeletePerAccountPerDay:   cfg.DeletePerAccountPerDay,
		DeleteResendCooldown:     cfg.DeleteResendCooldown,
	}, queries, privacy.NewLogNotifier(nil), recorder)
	if err != nil {
		t.Fatalf("privacy.New rejected the loaded config: %v", err)
	}
	if svc.GracePeriod() != cfg.GracePeriod {
		t.Errorf("service GracePeriod = %v, want the loaded %v", svc.GracePeriod(), cfg.GracePeriod)
	}

	opener, err := privacy.NewPgSubjectTxOpener(noopTransacter{})
	if err != nil {
		t.Fatalf("NewPgSubjectTxOpener: %v", err)
	}
	if _, err := privacy.NewPurger(privacy.PurgeConfig{
		GracePeriod: cfg.GracePeriod,
		BatchSize:   cfg.PurgeBatchSize,
		DryRun:      cfg.PurgeDryRun,
	}, queries, opener, recorder); err != nil {
		t.Fatalf("privacy.NewPurger rejected the loaded config: %v", err)
	}
}

// noopTransacter satisfies privacy.Transacter for construction-only assertions. It
// is never asked to begin a transaction.
type noopTransacter struct{}

func (noopTransacter) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("config: noopTransacter must not be used")
}
