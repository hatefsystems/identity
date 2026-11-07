//go:build integration

package server

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func TestAdminOperatorRoleEligibilityNoopsAndRollbackIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	ctx := t.Context()
	operator := uuid.New()
	q := db.New(f.pool)
	counts := func(target uuid.UUID) [3]int64 {
		t.Helper()
		var counts [3]int64
		if err := f.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM user_roles WHERE user_id=$1),
			(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1),
			(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2)`, target, operator.String()).Scan(&counts[0], &counts[1], &counts[2]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	for _, tc := range []struct {
		name, status                   string
		mfa, passkey, deleted, allowed bool
	}{
		{"no MFA", "active", false, false, false, false},
		{"TOTP", "active", true, false, false, true},
		{"passkey", "active", false, true, false, true},
		{"banned", "banned", true, false, false, false},
		{"suspended", "suspended", true, false, false, false},
		{"pending deletion", "pending_deletion", true, false, false, false},
		{"soft deleted", "active", true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := f.user(t).ID
			if _, err := f.pool.Exec(ctx, `UPDATE users SET status=$2,is_mfa_enabled=$3,
				deleted_at=CASE WHEN $4 THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=$1`, target, tc.status, tc.mfa, tc.deleted); err != nil {
				t.Fatal(err)
			}
			if tc.passkey {
				// Enrollment validity is tested by WebAuthn; provisioning consumes
				// the persisted credential-presence fact, not a new ceremony.
				if _, err := f.pool.Exec(ctx, `INSERT INTO webauthn_credentials
					(id,user_id,public_key,attestation_type,aaguid) VALUES($1,$2,$3,'none',$4)`, []byte(uuid.NewString()), target, []byte{1}, uuid.New()); err != nil {
					t.Fatal(err)
				}
			}
			before := counts(target)
			err := rbac.ProvisionRole(ctx, f.srv.deps.AdminActions, operator, "spiffe://identity.test/operator", target, "dpo", false, "test")
			if (err == nil) != tc.allowed {
				t.Fatalf("grant eligibility mismatch: allowed=%v err=%v", tc.allowed, err)
			}
			if !tc.allowed {
				if counts(target) != before {
					t.Fatal("rejected operator grant wrote role/context/outbox state")
				}
				return
			}
			if err := rbac.ProvisionRole(ctx, f.srv.deps.AdminActions, operator, "spiffe://identity.test/operator", target, "dpo", false, "test"); err != nil {
				t.Fatal(err)
			}
			// Revocation remains possible after the target loses eligibility.
			if _, err := f.pool.Exec(ctx, "UPDATE users SET status='banned',is_mfa_enabled=false WHERE id=$1", target); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := rbac.ProvisionRole(ctx, f.srv.deps.AdminActions, operator, "spiffe://identity.test/operator", target, "dpo", true, "test"); err != nil {
					t.Fatal(err)
				}
			}
			if held, err := q.UserHasRole(ctx, db.UserHasRoleParams{UserID: target, RoleID: "dpo"}); err != nil || held {
				t.Fatal("inactive-target revoke failed")
			}
			rows, err := f.pool.Query(ctx, `SELECT o.payload FROM event_outbox o
				JOIN admin_action_contexts c ON c.action_id=o.id WHERE c.account_ref=$1 ORDER BY c.created_at,o.id`, target)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var events, noops int
			for rows.Next() {
				var payload []byte
				if err := rows.Scan(&payload); err != nil {
					t.Fatal(err)
				}
				var env audit.Envelope
				var metadata struct {
					Noop bool `json:"noop"`
				}
				if json.Unmarshal(payload, &env) != nil || json.Unmarshal([]byte(env.Payload), &metadata) != nil || env.ActorID != operator.String() || env.ActorSPIFFEID != "spiffe://identity.test/operator" {
					t.Fatal("operator attribution/no-op audit missing")
				}
				events++
				if metadata.Noop {
					noops++
				}
			}
			if err := rows.Err(); err != nil || events != 4 || noops != 2 {
				t.Fatalf("operator noops were not independently audited: events=%d noops=%d err=%v", events, noops, err)
			}
			var invalidClocks int
			if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1 AND retain_until-created_at<>interval '1 hour'", target).Scan(&invalidClocks); err != nil || invalidClocks != 0 {
				t.Fatal("operator context retention was not derived from baseline")
			}
		})
	}
	target := f.user(t).ID
	if _, err := f.pool.Exec(ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", target); err != nil {
		t.Fatal(err)
	}
	before := counts(target)
	for _, tc := range []struct {
		name    string
		actions *adminaction.Service
		want    error
	}{
		{"mismatch", operatorTestActions(t, f, false, 2*time.Hour), legalpolicy.ErrMismatch},
		{"audit insert failure", operatorTestActions(t, f, true, time.Hour), adminaction.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rbac.ProvisionRole(ctx, tc.actions, operator, "spiffe://identity.test/operator", target, "dpo", false, "test")
			if !errors.Is(err, tc.want) || counts(target) != before {
				t.Fatalf("failed operator mutation committed state: err=%v", err)
			}
		})
	}
}

func operatorTestActions(t *testing.T, f *adminIntegration, reject bool, retention time.Duration) *adminaction.Service {
	t.Helper()
	var beginner adminaction.Beginner = f.pool
	if reject {
		beginner = rejectAuditBeginner{f.pool}
	}
	actions, err := adminaction.New(beginner, f.enc, "identity.audit.admin-test", retention)
	if err != nil {
		t.Fatal(err)
	}
	return actions
}
