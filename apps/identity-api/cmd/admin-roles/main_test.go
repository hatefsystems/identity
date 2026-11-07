package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
)

type roleBaselineStore struct {
	db.DBTX
	id       uuid.UUID
	artifact []byte
	err      error
}

func TestRoleCommandRequiresEnvironmentBeforeConfiguration(t *testing.T) {
	for _, raw := range []string{"missing", "", " ", "staging", "development ", "TEST"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("APP_ENV", raw)
			if raw == "missing" {
				if err := os.Unsetenv("APP_ENV"); err != nil {
					t.Fatal(err)
				}
			}
			err := run(t.Context(), "invalid-user", "support", false)
			if err == nil || !strings.Contains(err.Error(), "APP_ENV") {
				t.Fatalf("mode not rejected first: %v", err)
			}
		})
	}
}

func TestRoleCommandValidatesOnlyOwnedDependenciesBeforePool(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	t.Setenv("ADMIN_OPERATOR_ID", uuid.NewString())
	t.Setenv("ADMIN_OPERATOR_SPIFFE_ID", "spiffe://identity.test/operator")
	t.Setenv("DATABASE_URL", "invalid-owned-role-dsn")
	t.Setenv(config.EnvMasterKEK, base64.StdEncoding.EncodeToString(key))
	t.Setenv(config.EnvMasterKEKVersion, "")
	t.Setenv(config.EnvAuditSubject, "identity.audit.logs")
	for _, field := range []string{config.EnvBlindIndexPepper, config.EnvBlindIndexPepperVersion, config.EnvOIDCIssuer, config.EnvOIDCClients, config.EnvOIDCSigningKey, "SMS_GATEWAY_API_KEY", config.EnvAuditBatchSize, config.EnvAuditAckWait} {
		t.Setenv(field, "unrelated-invalid-setting")
	}
	t.Setenv(config.EnvNATSURL, "")
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("APP_ENV", environment)
			err := run(t.Context(), uuid.NewString(), "support", false)
			if err == nil || !strings.Contains(err.Error(), "invalid-owned-role-dsn") {
				t.Fatalf("DB-only command blocked by unrelated settings: %v", err)
			}
		})
	}
	t.Setenv("APP_ENV", "production")
	t.Setenv(config.EnvMasterKEK, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	err := run(t.Context(), uuid.NewString(), "support", false)
	if err == nil || !strings.Contains(err.Error(), config.EnvMasterKEK) {
		t.Fatalf("public key not rejected before pool: %v", err)
	}
}

func TestRoleCommandHelpIndependentOfEnvironmentAndSecrets(t *testing.T) {
	if os.Getenv("ROLE_HELP_TEST") == "1" {
		flag.CommandLine = flag.NewFlagSet("admin-roles", flag.ExitOnError)
		os.Args = []string{"admin-roles", "-h"}
		main()
		return
	}
	t.Setenv("APP_ENV", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv(config.EnvMasterKEK, "")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("current test executable is unavailable")
	}
	// #nosec G204 -- Relaunch the system-resolved test binary with a fixed selector.
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestRoleCommandHelpIndependentOfEnvironmentAndSecrets$")
	cmd.Env = append(os.Environ(), "ROLE_HELP_TEST=1")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "target account UUID") {
		t.Fatalf("help requires runtime settings: %s, %v", output, err)
	}
}

type roleBaselineRow func(...any) error

func (row roleBaselineRow) Scan(dst ...any) error { return row(dst...) }

func (s roleBaselineStore) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	return roleBaselineRow(func(dst ...any) error {
		if s.err != nil {
			return s.err
		}
		*dst[0].(*uuid.UUID) = s.id
		if strings.Contains(query, "GetLegalGovernancePolicy") {
			*dst[1].(*[]byte) = s.artifact
		}
		return nil
	})
}

func TestRoleOperatorLoadsAndDerivesPersistedPolicy(t *testing.T) {
	policy := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "fixture-approval", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 7200,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry}
	artifact, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contextValue, releasedValue, policyID, environment string
		contextRetention, releasedRetention                      time.Duration
		storeErr, want                                           error
	}{
		{"derived without overrides", "", "", "", "test", 0, 0, nil, nil},
		{"matching supplied config", "1h", "2h", policy.ID.String(), "test", time.Hour, 2 * time.Hour, nil, nil},
		{"context mismatch", "2h", "", "", "test", 2 * time.Hour, 0, nil, legalpolicy.ErrMismatch},
		{"explicit zero rejected", "0s", "", "", "test", 0, 0, nil, legalpolicy.ErrMismatch},
		{"released mismatch", "", "1h", "", "test", 0, time.Hour, nil, legalpolicy.ErrMismatch},
		{"wrong policy binding", "", "", uuid.NewString(), "test", 0, 0, nil, legalpolicy.ErrMismatch},
		{"zero policy binding", "", "", uuid.Nil.String(), "test", 0, 0, nil, legalpolicy.ErrInvalidPolicy},
		{"missing policy", "", "", "", "test", 0, 0, pgx.ErrNoRows, legalpolicy.ErrNotApproved},
		{"unavailable policy", "", "", "", "test", 0, 0, errors.New("private-db-sentinel"), legalpolicy.ErrUnavailable},
		{"production fixture", "", "", "", "production", 0, 0, nil, legalpolicy.ErrInvalidPolicy},
		{"unknown fixture environment", "", "", "", "developmnt", 0, 0, nil, legalpolicy.ErrInvalidPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvAdminContextRetention, tc.contextValue)
			t.Setenv(config.EnvAdminLegalReleasedRetention, tc.releasedValue)
			p, err := loadOperatorBaseline(t.Context(), roleBaselineStore{id: policy.ID, artifact: artifact, err: tc.storeErr},
				config.AdminConfig{GovernancePolicyID: tc.policyID, ContextRetention: tc.contextRetention, LegalReleasedRetention: tc.releasedRetention}, tc.environment)
			if !errors.Is(err, tc.want) || (err == nil && (p.ID != policy.ID || p.ContextRetention() != time.Hour)) {
				t.Fatalf("operator baseline result err=%v retention=%s", err, p.ContextRetention())
			}
		})
	}
}
