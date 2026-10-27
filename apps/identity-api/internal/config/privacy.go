package config

import (
	"fmt"
	"time"
)

// PrivacyConfig holds the GDPR "Right to be Forgotten" policy (Task 5.1): the
// grace window, the purge worker's batch behaviour, and the abuse bounds on the
// deletion and reclaim endpoints.
//
// Every field is a non-sensitive tunable with a production-safe default. There is
// deliberately no reclaim-token TTL here: the token's expiry is derived as
// deleted_at + GracePeriod, so the token and the purge cutoff cannot be
// configured into disagreement (a token outliving the cutoff would point at an
// account that no longer exists; a token expiring early would silently shorten
// the recovery window the user was promised).
type PrivacyConfig struct {
	// DeletionEnabled permits new requests only after mailbox and delivery rollout
	// gates are satisfied. Recovery and notification draining remain independent.
	DeletionEnabled bool
	// GracePeriod is the recovery window between soft deactivation and physical
	// erasure (default 720h = 30 days). Every document describing it says 30 days
	// (docs/architecture.md "Grace Period & Soft Deletes",
	// docs/compliance-and-data-governance.md §4), and it is simultaneously the
	// purge cutoff and the reclaim-token lifetime. Production is fixed at 720h;
	// development/test may shorten it down to MinGDPRGracePeriod.
	GracePeriod time.Duration

	// PurgeBatchSize bounds how many subjects one worker run considers (default
	// 100). Each subject is purged in its own transaction, so this caps the run's
	// duration rather than the size of any single transaction.
	PurgeBatchSize int
	// PurgeDryRun makes the worker perform every read and decision, log the
	// intended outcome, and roll back without deleting or enqueuing (default
	// false). It is the safe way to validate a cutoff change against production
	// data.
	PurgeDryRun bool

	// ReclaimMaxAttempts is how many failed factor checks one reclaim request
	// tolerates before it is retired (default 5). A wrong factor never consumes
	// the token — that would destroy the account's only recovery path — so this
	// cap, not single use, is what bounds brute force against the ceremony.
	ReclaimMaxAttempts int
	// ReclaimPerAccountPerHour / ReclaimPerSubnetPerHour bound reclaim attempts
	// (defaults 10, 20). The subnet window is evaluated first so a saturated
	// shared proxy cannot burn a targeted account's budget.
	ReclaimPerAccountPerHour int
	ReclaimPerSubnetPerHour  int

	// DeletePerAccountPerDay bounds how often one account may call
	// DELETE /api/v1/users/me (default 3). The endpoint is idempotent, so this is
	// an abuse bound rather than a correctness one.
	DeletePerAccountPerDay int
}

// Environment variable names for the GDPR/privacy configuration.
const (
	EnvGDPRDeletionEnabled          = "GDPR_DELETION_ENABLED"
	EnvGDPRGracePeriod              = "GDPR_GRACE_PERIOD"
	EnvGDPRPurgeBatchSize           = "GDPR_PURGE_BATCH_SIZE"
	EnvGDPRPurgeDryRun              = "GDPR_PURGE_DRY_RUN"
	EnvGDPRReclaimMaxAttempts       = "GDPR_RECLAIM_MAX_ATTEMPTS"
	EnvGDPRReclaimPerAccountPerHour = "GDPR_RECLAIM_PER_ACCOUNT_PER_HOUR"
	EnvGDPRReclaimPerSubnetPerHour  = "GDPR_RECLAIM_PER_SUBNET_PER_HOUR"
	EnvGDPRDeletePerAccountPerDay   = "GDPR_DELETE_PER_ACCOUNT_PER_DAY"
)

// GDPR/privacy default policy values (docs/architecture.md "Grace Period & Soft
// Deletes", docs/compliance-and-data-governance.md §4).
const (
	// defaultGDPRGracePeriod is the documented 30-day recovery window.
	defaultGDPRGracePeriod = 720 * time.Hour
	// MinGDPRGracePeriod is the floor below which the grace window stops being a
	// usable recovery mechanism. It is exported so the privacy service and its
	// tests assert the same boundary the loader enforces.
	MinGDPRGracePeriod = 24 * time.Hour

	defaultGDPRPurgeBatchSize           = 100
	defaultGDPRPurgeDryRun              = false
	defaultGDPRReclaimMaxAttempts       = 5
	defaultGDPRReclaimPerAccountPerHour = 10
	defaultGDPRReclaimPerSubnetPerHour  = 20
	defaultGDPRDeletePerAccountPerDay   = 3
)

// LoadPrivacy builds a PrivacyConfig from environment variables, applying the
// documented defaults for every unset tunable and failing fast on a malformed
// value or a grace window below the mandated floor.
//
// Outside development/test, the recovery window is exactly the published 30 days.
func LoadPrivacy(environment string) (PrivacyConfig, error) {
	cfg := PrivacyConfig{
		GracePeriod:              defaultGDPRGracePeriod,
		PurgeBatchSize:           defaultGDPRPurgeBatchSize,
		PurgeDryRun:              defaultGDPRPurgeDryRun,
		ReclaimMaxAttempts:       defaultGDPRReclaimMaxAttempts,
		ReclaimPerAccountPerHour: defaultGDPRReclaimPerAccountPerHour,
		ReclaimPerSubnetPerHour:  defaultGDPRReclaimPerSubnetPerHour,
		DeletePerAccountPerDay:   defaultGDPRDeletePerAccountPerDay,
	}

	var err error
	if cfg.DeletionEnabled, err = getEnvBool(EnvGDPRDeletionEnabled, false); err != nil {
		return PrivacyConfig{}, err
	}
	// getEnvDuration already rejects a non-positive value, so only the floor is
	// checked here.
	if cfg.GracePeriod, err = getEnvDuration(EnvGDPRGracePeriod, defaultGDPRGracePeriod); err != nil {
		return PrivacyConfig{}, err
	}
	if cfg.GracePeriod < MinGDPRGracePeriod {
		return PrivacyConfig{}, fmt.Errorf(
			"config: %s %v is below the %v minimum recovery window",
			EnvGDPRGracePeriod, cfg.GracePeriod, MinGDPRGracePeriod)
	}
	if environment != "development" && environment != "test" && cfg.GracePeriod != defaultGDPRGracePeriod {
		return PrivacyConfig{}, fmt.Errorf("config: %s must be 720h outside development/test", EnvGDPRGracePeriod)
	}
	if cfg.PurgeBatchSize, err = getEnvPositiveInt(
		EnvGDPRPurgeBatchSize, defaultGDPRPurgeBatchSize); err != nil {
		return PrivacyConfig{}, err
	}
	if cfg.PurgeDryRun, err = getEnvBool(EnvGDPRPurgeDryRun, defaultGDPRPurgeDryRun); err != nil {
		return PrivacyConfig{}, err
	}
	if cfg.ReclaimMaxAttempts, err = getEnvPositiveInt(
		EnvGDPRReclaimMaxAttempts, defaultGDPRReclaimMaxAttempts); err != nil {
		return PrivacyConfig{}, err
	}
	if cfg.ReclaimPerAccountPerHour, err = getEnvPositiveInt(
		EnvGDPRReclaimPerAccountPerHour, defaultGDPRReclaimPerAccountPerHour); err != nil {
		return PrivacyConfig{}, err
	}
	if cfg.ReclaimPerSubnetPerHour, err = getEnvPositiveInt(
		EnvGDPRReclaimPerSubnetPerHour, defaultGDPRReclaimPerSubnetPerHour); err != nil {
		return PrivacyConfig{}, err
	}
	if cfg.DeletePerAccountPerDay, err = getEnvPositiveInt(
		EnvGDPRDeletePerAccountPerDay, defaultGDPRDeletePerAccountPerDay); err != nil {
		return PrivacyConfig{}, err
	}
	return cfg, nil
}
