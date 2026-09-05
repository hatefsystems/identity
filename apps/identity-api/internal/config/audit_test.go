package config

import (
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
)

// clearAuditEnv unsets every audit variable so a test starts from a known state
// regardless of the ambient environment (t.Setenv restores them on cleanup).
func clearAuditEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EnvNATSURL,
		EnvAuditStreamName,
		EnvAuditSubject,
		EnvAuditConsumerName,
		EnvAuditPublishBuffer,
		EnvAuditBatchSize,
		EnvAuditFlushInterval,
		EnvAuditStreamMaxBytes,
		EnvAuditAckWait,
		EnvAuditMaxDeliver,
		EnvSecurityLedgerRetention,
	} {
		t.Setenv(k, "")
	}
}

func TestLoadAuditDefaults(t *testing.T) {
	clearAuditEnv(t)
	t.Setenv(EnvNATSURL, "nats://localhost:4222")

	cfg, err := LoadAudit("production")
	if err != nil {
		t.Fatalf("LoadAudit: %v", err)
	}
	if cfg.StreamName != defaultAuditStreamName {
		t.Errorf("StreamName = %q, want %q", cfg.StreamName, defaultAuditStreamName)
	}
	if cfg.Subject != defaultAuditSubject {
		t.Errorf("Subject = %q, want %q", cfg.Subject, defaultAuditSubject)
	}
	if cfg.ConsumerName != defaultAuditConsumerName {
		t.Errorf("ConsumerName = %q, want %q", cfg.ConsumerName, defaultAuditConsumerName)
	}
	if cfg.PublishBuffer != defaultAuditPublishBuffer {
		t.Errorf("PublishBuffer = %d, want %d", cfg.PublishBuffer, defaultAuditPublishBuffer)
	}
	// docs/data-architecture.md §4.2 specifies "every 5s or 1000 records"; assert both
	// halves of that sentence, not just the constants they were copied into.
	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize = %d, want the documented 1000", cfg.BatchSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want the documented 5s", cfg.FlushInterval)
	}
	if cfg.StreamMaxBytes != defaultAuditStreamMaxBytes {
		t.Errorf("StreamMaxBytes = %d, want %d", cfg.StreamMaxBytes, defaultAuditStreamMaxBytes)
	}
	if cfg.DuplicateWindow != defaultAuditDuplicateWindow {
		t.Errorf("DuplicateWindow = %v, want %v", cfg.DuplicateWindow, defaultAuditDuplicateWindow)
	}
	if cfg.AckWait != defaultAuditAckWait {
		t.Errorf("AckWait = %v, want %v", cfg.AckWait, defaultAuditAckWait)
	}
	if cfg.MaxDeliver != defaultAuditMaxDeliver {
		t.Errorf("MaxDeliver = %d, want %d", cfg.MaxDeliver, defaultAuditMaxDeliver)
	}
	if cfg.LedgerRetention != defaultSecurityLedgerRetention {
		t.Errorf("LedgerRetention = %v, want %v", cfg.LedgerRetention, defaultSecurityLedgerRetention)
	}
	if !cfg.HasNATS() {
		t.Error("HasNATS() = false with NATS_URL set, want true")
	}
}

func TestLoadAuditOverrides(t *testing.T) {
	clearAuditEnv(t)
	t.Setenv(EnvNATSURL, "  nats://bus.internal:4222  ")
	t.Setenv(EnvAuditStreamName, "AUDIT_ALT")
	t.Setenv(EnvAuditSubject, "identity.audit.v2")
	t.Setenv(EnvAuditConsumerName, "audit-signer-canary")
	t.Setenv(EnvAuditPublishBuffer, "64")
	t.Setenv(EnvAuditBatchSize, "250")
	t.Setenv(EnvAuditFlushInterval, "2s")
	t.Setenv(EnvAuditStreamMaxBytes, "1048576")
	t.Setenv(EnvAuditAckWait, "90s")
	t.Setenv(EnvAuditMaxDeliver, "3")
	t.Setenv(EnvSecurityLedgerRetention, "5000h")

	cfg, err := LoadAudit("production")
	if err != nil {
		t.Fatalf("LoadAudit: %v", err)
	}
	// The URL is trimmed: a trailing newline from a mounted secret file must not
	// become part of the dial target, and must not make HasNATS report a bus that
	// cannot be reached.
	if cfg.NATSURL != "nats://bus.internal:4222" {
		t.Errorf("NATSURL = %q, want the trimmed URL", cfg.NATSURL)
	}
	if cfg.StreamName != "AUDIT_ALT" {
		t.Errorf("StreamName = %q, want AUDIT_ALT", cfg.StreamName)
	}
	if cfg.Subject != "identity.audit.v2" {
		t.Errorf("Subject = %q, want identity.audit.v2", cfg.Subject)
	}
	if cfg.ConsumerName != "audit-signer-canary" {
		t.Errorf("ConsumerName = %q, want audit-signer-canary", cfg.ConsumerName)
	}
	if cfg.PublishBuffer != 64 {
		t.Errorf("PublishBuffer = %d, want 64", cfg.PublishBuffer)
	}
	if cfg.BatchSize != 250 {
		t.Errorf("BatchSize = %d, want 250", cfg.BatchSize)
	}
	if cfg.FlushInterval != 2*time.Second {
		t.Errorf("FlushInterval = %v, want 2s", cfg.FlushInterval)
	}
	if cfg.StreamMaxBytes != 1<<20 {
		t.Errorf("StreamMaxBytes = %d, want 1048576", cfg.StreamMaxBytes)
	}
	if cfg.AckWait != 90*time.Second {
		t.Errorf("AckWait = %v, want 90s", cfg.AckWait)
	}
	if cfg.MaxDeliver != 3 {
		t.Errorf("MaxDeliver = %d, want 3", cfg.MaxDeliver)
	}
	if cfg.LedgerRetention != 5000*time.Hour {
		t.Errorf("LedgerRetention = %v, want 5000h", cfg.LedgerRetention)
	}
}

// TestLoadAuditNATSURLRequirement pins the one environment-dependent decision in
// this loader. In development an absent bus is a convenience: the caller falls back
// to the log recorder and the service still boots. Outside development the same
// absence is a silent loss of the audit trail, because nothing downstream would ever
// write mvp_audit_logs — so it must refuse to start.
func TestLoadAuditNATSURLRequirement(t *testing.T) {
	t.Run("DevelopmentAllowsAbsentBus", func(t *testing.T) {
		clearAuditEnv(t)

		cfg, err := LoadAudit("development")
		if err != nil {
			t.Fatalf("LoadAudit in development: %v", err)
		}
		if cfg.HasNATS() {
			t.Error("HasNATS() = true with no NATS_URL, want false so the caller selects the log fallback")
		}
		// The rest of the policy must still be populated: development uses the same
		// batching and retention numbers as production.
		if cfg.BatchSize != defaultAuditBatchSize || cfg.Subject != defaultAuditSubject {
			t.Errorf("development config was not fully populated: %+v", cfg)
		}
	})

	for _, env := range []string{"production", "staging", ""} {
		t.Run("Rejected/"+env, func(t *testing.T) {
			clearAuditEnv(t)

			_, err := LoadAudit(env)
			if err == nil {
				t.Fatalf("LoadAudit(%q) with no NATS_URL = nil error, want error", env)
			}
			if !strings.Contains(err.Error(), EnvNATSURL) {
				t.Errorf("error %q does not name %s", err, EnvNATSURL)
			}
		})
	}

	// Whitespace is not a URL. Without the trim this would pass the emptiness check
	// and then fail at dial time, long after startup validation was supposed to catch
	// it.
	t.Run("WhitespaceIsNotAURL", func(t *testing.T) {
		clearAuditEnv(t)
		t.Setenv(EnvNATSURL, "   ")

		if _, err := LoadAudit("production"); err == nil {
			t.Fatal("LoadAudit with a blank NATS_URL = nil error, want error")
		}
	})
}

// TestLoadAuditSubjectMustBeBoundToStream guards the pipeline's quietest failure
// mode: a subject outside the stream's subject space leaves a healthy-looking
// service publishing into nothing, with an empty ledger and no error anywhere except
// the fallback log.
func TestLoadAuditSubjectMustBeBoundToStream(t *testing.T) {
	accepted := []string{"identity.audit.logs", "identity.audit.v2", "identity.audit.a.b"}
	for _, subject := range accepted {
		t.Run("Accepted/"+subject, func(t *testing.T) {
			clearAuditEnv(t)
			t.Setenv(EnvNATSURL, "nats://localhost:4222")
			t.Setenv(EnvAuditSubject, subject)

			cfg, err := LoadAudit("production")
			if err != nil {
				t.Fatalf("LoadAudit with subject %q: %v", subject, err)
			}
			if cfg.Subject != subject {
				t.Errorf("Subject = %q, want %q", cfg.Subject, subject)
			}
		})
	}

	rejected := []string{"identity.user.created", "audit.logs", "identity.audit", "identity.auditlogs", ""}
	for _, subject := range rejected {
		t.Run("Rejected/"+subject, func(t *testing.T) {
			clearAuditEnv(t)
			t.Setenv(EnvNATSURL, "nats://localhost:4222")
			t.Setenv(EnvAuditSubject, subject)

			// An empty value falls back to the default, which is valid; only a
			// non-empty out-of-space subject can be rejected.
			if subject == "" {
				cfg, err := LoadAudit("production")
				if err != nil {
					t.Fatalf("LoadAudit with an unset subject: %v", err)
				}
				if cfg.Subject != defaultAuditSubject {
					t.Errorf("Subject = %q, want the default %q", cfg.Subject, defaultAuditSubject)
				}
				return
			}
			if _, err := LoadAudit("production"); err == nil {
				t.Fatalf("LoadAudit with subject %q = nil error, want error", subject)
			}
		})
	}
}

// TestLoadAuditLedgerRetentionWindow pins all four boundaries of the mandated
// 6-to-18-month window. Both ends are enforced because both are compliance
// failures: too short destroys evidence the platform must be able to produce, too
// long keeps request-linkable data past its lawful purpose.
func TestLoadAuditLedgerRetentionWindow(t *testing.T) {
	cases := []struct {
		name    string
		value   time.Duration
		wantErr bool
	}{
		{"AtMinimum", MinSecurityLedgerRetention, false},
		{"JustBelowMinimum", MinSecurityLedgerRetention - time.Nanosecond, true},
		{"AtMaximum", MaxSecurityLedgerRetention, false},
		{"JustAboveMaximum", MaxSecurityLedgerRetention + time.Nanosecond, true},
		{"WellInside", 8760 * time.Hour, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAuditEnv(t)
			t.Setenv(EnvNATSURL, "nats://localhost:4222")
			t.Setenv(EnvSecurityLedgerRetention, tc.value.String())

			cfg, err := LoadAudit("production")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("LoadAudit with %s=%v = nil error, want error",
						EnvSecurityLedgerRetention, tc.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadAudit with %s=%v: %v", EnvSecurityLedgerRetention, tc.value, err)
			}
			if cfg.LedgerRetention != tc.value {
				t.Errorf("LedgerRetention = %v, want %v", cfg.LedgerRetention, tc.value)
			}
		})
	}

	// The default must sit inside the window it is validated against; otherwise an
	// unconfigured deployment could not start at all.
	if defaultSecurityLedgerRetention < MinSecurityLedgerRetention ||
		defaultSecurityLedgerRetention > MaxSecurityLedgerRetention {
		t.Errorf("default retention %v is outside the enforced window %v-%v",
			defaultSecurityLedgerRetention, MinSecurityLedgerRetention, MaxSecurityLedgerRetention)
	}
}

// TestLoadAuditAckWaitCoversBatchLifetime asserts the cross-field invariant. An
// AckWait shorter than fill time plus commit time makes JetStream redeliver batches
// that are still being written: the signer would do duplicate work forever while the
// consumer never drains, and nothing in the logs would identify configuration as the
// cause.
func TestLoadAuditAckWaitCoversBatchLifetime(t *testing.T) {
	const flush = "5s"
	minAckWait := 5*time.Second + signer.BatchTimeout

	t.Run("BelowSumRejected", func(t *testing.T) {
		clearAuditEnv(t)
		t.Setenv(EnvNATSURL, "nats://localhost:4222")
		t.Setenv(EnvAuditFlushInterval, flush)
		t.Setenv(EnvAuditAckWait, minAckWait.String())

		if _, err := LoadAudit("production"); err == nil {
			t.Fatalf("LoadAudit with AckWait exactly at the %v floor = nil error, want error", minAckWait)
		}
	})

	t.Run("AboveSumAccepted", func(t *testing.T) {
		clearAuditEnv(t)
		t.Setenv(EnvNATSURL, "nats://localhost:4222")
		t.Setenv(EnvAuditFlushInterval, flush)
		t.Setenv(EnvAuditAckWait, (minAckWait + time.Second).String())

		if _, err := LoadAudit("production"); err != nil {
			t.Fatalf("LoadAudit just above the floor: %v", err)
		}
	})

	// A long flush interval must drag the required AckWait up with it, rather than
	// being validated against a fixed literal.
	t.Run("FlushIntervalRaisesTheFloor", func(t *testing.T) {
		clearAuditEnv(t)
		t.Setenv(EnvNATSURL, "nats://localhost:4222")
		t.Setenv(EnvAuditFlushInterval, "60s")
		t.Setenv(EnvAuditAckWait, defaultAuditAckWait.String())

		if _, err := LoadAudit("production"); err == nil {
			t.Fatal("LoadAudit with a 60s flush interval and the default 60s AckWait = nil error, want error")
		}
	})

	// The shipped defaults must satisfy their own invariant.
	t.Run("DefaultsSatisfyTheInvariant", func(t *testing.T) {
		if defaultAuditAckWait <= defaultAuditFlushInterval+signer.BatchTimeout {
			t.Errorf("default AckWait %v does not exceed flush %v + batch timeout %v",
				defaultAuditAckWait, defaultAuditFlushInterval, signer.BatchTimeout)
		}
	})
}

func TestLoadAuditMalformedValues(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"PublishBufferNotAnInt", EnvAuditPublishBuffer, "plenty"},
		{"PublishBufferZero", EnvAuditPublishBuffer, "0"},
		{"PublishBufferNegative", EnvAuditPublishBuffer, "-1"},
		{"BatchSizeNotAnInt", EnvAuditBatchSize, "thousand"},
		{"BatchSizeZero", EnvAuditBatchSize, "0"},
		{"BatchSizeNegative", EnvAuditBatchSize, "-10"},
		{"FlushIntervalNotADuration", EnvAuditFlushInterval, "5 seconds"},
		{"FlushIntervalZero", EnvAuditFlushInterval, "0s"},
		{"FlushIntervalNegative", EnvAuditFlushInterval, "-5s"},
		{"StreamMaxBytesNotAnInt", EnvAuditStreamMaxBytes, "512MB"},
		{"StreamMaxBytesZero", EnvAuditStreamMaxBytes, "0"},
		{"StreamMaxBytesNegative", EnvAuditStreamMaxBytes, "-1"},
		{"AckWaitNotADuration", EnvAuditAckWait, "a minute"},
		{"AckWaitZero", EnvAuditAckWait, "0s"},
		{"MaxDeliverNotAnInt", EnvAuditMaxDeliver, "five"},
		{"MaxDeliverZero", EnvAuditMaxDeliver, "0"},
		{"MaxDeliverNegative", EnvAuditMaxDeliver, "-2"},
		{"RetentionNotADuration", EnvSecurityLedgerRetention, "one year"},
		{"RetentionZero", EnvSecurityLedgerRetention, "0s"},
		{"RetentionNegative", EnvSecurityLedgerRetention, "-8760h"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAuditEnv(t)
			t.Setenv(EnvNATSURL, "nats://localhost:4222")
			t.Setenv(tc.key, tc.value)

			if _, err := LoadAudit("production"); err == nil {
				t.Fatalf("LoadAudit with %s=%q = nil error, want error", tc.key, tc.value)
			}
		})
	}
}

// TestLoadAuditDerivedValues covers the fields that are computed rather than read,
// because a wrong derivation here is invisible in the environment.
func TestLoadAuditDerivedValues(t *testing.T) {
	clearAuditEnv(t)
	t.Setenv(EnvNATSURL, "nats://localhost:4222")
	t.Setenv(EnvAuditBatchSize, "250")

	cfg, err := LoadAudit("production")
	if err != nil {
		t.Fatalf("LoadAudit: %v", err)
	}

	// MaxAckPending must leave room for a second batch: at exactly BatchSize the
	// consumer cannot stage the next fetch while the current batch commits.
	if got := cfg.MaxAckPending(); got != 500 {
		t.Errorf("MaxAckPending() = %d, want 500 (2 x BatchSize)", got)
	}
	if cfg.MaxAckPending() <= cfg.BatchSize {
		t.Errorf("MaxAckPending() = %d must exceed BatchSize %d", cfg.MaxAckPending(), cfg.BatchSize)
	}

	subjects := cfg.StreamSubjects()
	if len(subjects) != 1 || subjects[0] != StreamSubjectPattern {
		t.Errorf("StreamSubjects() = %v, want [%s]", subjects, StreamSubjectPattern)
	}
	// The declared subject must actually fall inside the stream's subject space —
	// the whole point of the prefix check.
	if !strings.HasPrefix(cfg.Subject, strings.TrimSuffix(StreamSubjectPattern, ">")) {
		t.Errorf("Subject %q is not covered by stream subjects %v", cfg.Subject, subjects)
	}
}

// TestLoadAuditFeedsSigner is a guard against config/domain drift: the batching
// values LoadAudit produces must be accepted unchanged by signer.New's own
// validation, so the two packages cannot disagree about what a legal batch is.
func TestLoadAuditFeedsSigner(t *testing.T) {
	clearAuditEnv(t)
	t.Setenv(EnvNATSURL, "nats://localhost:4222")

	cfg, err := LoadAudit("production")
	if err != nil {
		t.Fatalf("LoadAudit: %v", err)
	}

	sc := signer.Config{
		BatchSize:       cfg.BatchSize,
		FlushInterval:   cfg.FlushInterval,
		LedgerRetention: cfg.LedgerRetention,
	}
	if sc.BatchSize <= 0 || sc.FlushInterval <= 0 || sc.LedgerRetention <= 0 {
		t.Fatalf("loaded config produces a signer.Config signer.New would reject: %+v", sc)
	}
}
