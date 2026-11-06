package main

import (
	"context"
	"encoding/json"
	"errors"
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
