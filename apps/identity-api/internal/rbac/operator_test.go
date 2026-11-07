package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
)

type operatorPolicyTx struct {
	pgx.Tx
	id         uuid.UUID
	artifact   []byte
	loadErr    error
	queries    int
	locks      int
	rolledBack bool
}

type operatorPolicyRow func(...any) error

func (r operatorPolicyRow) Scan(dst ...any) error { return r(dst...) }

func (tx *operatorPolicyTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	tx.queries++
	return operatorPolicyRow(func(dst ...any) error {
		if tx.loadErr != nil {
			return tx.loadErr
		}
		*dst[0].(*uuid.UUID) = tx.id
		if strings.Contains(query, "GetLegalGovernancePolicy") {
			*dst[1].(*[]byte) = tx.artifact
		}
		return nil
	})
}

var errOperatorAccountLock = errors.New("operator account lock reached")

func (tx *operatorPolicyTx) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	if query != "SET TRANSACTION ISOLATION LEVEL READ COMMITTED" {
		tx.locks++
		return pgconn.CommandTag{}, errOperatorAccountLock
	}
	return pgconn.CommandTag{}, nil
}

func (tx *operatorPolicyTx) Rollback(context.Context) error { tx.rolledBack = true; return nil }

type operatorPolicyBeginner struct{ tx *operatorPolicyTx }

func (b operatorPolicyBeginner) Begin(context.Context) (pgx.Tx, error) { return b.tx, nil }

type operatorPolicyEncryptor struct{}

func (operatorPolicyEncryptor) Encrypt(context.Context, []byte) ([]byte, error) {
	panic("policy preflight must not encrypt context")
}

func TestProvisionRoleRequiresInstalledBaselineBeforeAccountMutation(t *testing.T) {
	policy := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "fixture-policy", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 7200,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry}
	artifact, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, environment string
		loadErr           error
		artifact          []byte
		retention         time.Duration
		want              error
		locks             int
	}{
		{"absent binding", "test", pgx.ErrNoRows, artifact, time.Hour, legalpolicy.ErrNotApproved, 0},
		{"inventory error", "test", errors.New("private-storage-error"), artifact, time.Hour, legalpolicy.ErrUnavailable, 0},
		{"invalid artifact", "test", nil, []byte(`{"fixture":null}`), time.Hour, legalpolicy.ErrInvalidPolicy, 0},
		{"production fixture", "production", nil, artifact, time.Hour, legalpolicy.ErrInvalidPolicy, 0},
		{"environment typo", "developmnt", nil, artifact, time.Hour, legalpolicy.ErrInvalidPolicy, 0},
		{"empty environment", "", nil, artifact, time.Hour, legalpolicy.ErrInvalidPolicy, 0},
		{"retention mismatch", "test", nil, artifact, 2 * time.Hour, legalpolicy.ErrMismatch, 0},
		{"installed baseline", "test", nil, artifact, time.Hour, errOperatorAccountLock, 1},
	} {
		for _, revoke := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/grant", true: "/revoke"}[revoke], func(t *testing.T) {
				tx := &operatorPolicyTx{id: policy.ID, artifact: tc.artifact, loadErr: tc.loadErr}
				actions, err := adminaction.New(operatorPolicyBeginner{tx}, operatorPolicyEncryptor{}, "identity.audit.operator", tc.retention)
				if err != nil {
					t.Fatal(err)
				}
				err = ProvisionRole(t.Context(), actions, uuid.New(), "spiffe://identity.test/operator", uuid.New(), "dpo", revoke, tc.environment)
				if !errors.Is(err, tc.want) || tx.locks != tc.locks || !tx.rolledBack {
					t.Fatalf("operator policy boundary err=%v locks=%d rollback=%v", err, tx.locks, tx.rolledBack)
				}
				if tx.queries < 1 || tx.queries > 2 {
					t.Fatal("operator did not resolve/revalidate the persisted baseline before target access")
				}
			})
		}
	}
}
