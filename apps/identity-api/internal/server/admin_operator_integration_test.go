//go:build integration

package server

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

func TestAdminOperatorRoleEligibilityNoopsAndRollbackIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	ctx := t.Context()
	operator := uuid.New()
	q := db.New(f.pool)
	counts := func(target uuid.UUID) [5]int64 {
		t.Helper()
		var counts [5]int64
		if err := f.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM user_roles WHERE user_id=$1),
			(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1),
			(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2),
			(SELECT auth_version FROM users WHERE id=$1),
			(SELECT auth_epoch FROM users WHERE id=$1)`, target, operator.String()).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	for _, tc := range []struct {
		name, status                   string
		mfa, passkey, deleted, allowed bool
	}{
		{"no MFA", "active", false, false, false, false},
		{"TOTP flag only", "active", true, false, false, false},
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
				f.passkey(t, target)
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
			granted := counts(target)
			if granted[3] != before[3]+1 || granted[4] <= before[4] {
				t.Fatal("real grant did not atomically advance authority")
			}
			if err := rbac.ProvisionRole(ctx, f.srv.deps.AdminActions, operator, "spiffe://identity.test/operator", target, "dpo", false, "test"); err != nil {
				t.Fatal(err)
			}
			if noop := counts(target); noop[3] != granted[3] || noop[4] != granted[4] {
				t.Fatal("no-op grant invalidated authority")
			}
			// Revocation remains possible after the target loses eligibility.
			if _, err := f.pool.Exec(ctx, "UPDATE users SET status='banned',is_mfa_enabled=false WHERE id=$1", target); err != nil {
				t.Fatal(err)
			}
			revoking := counts(target)
			for attempt := range 2 {
				if err := rbac.ProvisionRole(ctx, f.srv.deps.AdminActions, operator, "spiffe://identity.test/operator", target, "dpo", true, "test"); err != nil {
					t.Fatal(err)
				}
				revoked := counts(target)
				if revoked[3] != revoking[3]+1 || revoked[4] <= revoking[4] {
					t.Fatalf("revoke authority transition failed on attempt %d", attempt)
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
	f.passkey(t, target)
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

func TestAdminOperatorPrimaryCredentialAndConfiguredFactorIntegration(t *testing.T) {
	f, actions := newRoleProtectionFixture(t)
	policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}
	for _, tc := range []struct {
		name, credential, mutation string
		totp, enabled              bool
		want                       error
	}{
		{"password and configured TOTP", "password_only", "", true, true, nil},
		{"password without TOTP", "password_only", "", false, true, accountpolicy.ErrLastFactor},
		{"TOTP flag without secret", "password_only", "flag", false, true, accountpolicy.ErrLastFactor},
		{"TOTP secret without enabled flag", "password_only", "disabled", true, true, accountpolicy.ErrLastFactor},
		{"TOTP without primary credential", "password_only", "missing verifier", true, true, accountpolicy.ErrLastCredential},
		{"TOTP and malformed password", "password_only", "unsupported verifier", true, true, accountpolicy.ErrLastCredential},
		{"password login disabled", "password_only", "", true, false, accountpolicy.ErrLastCredential},
		{"password without admitted username", "password_unclaimed", "", true, true, accountpolicy.ErrLastCredential},
		{"password authority unavailable", "password_only", "no authority", true, true, username.ErrUnavailable},
		{"passkey default policy", "passkey_only", "", false, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := f.account(t, tc.credential, tc.totp)
			statement := map[string]string{
				"flag":                 `UPDATE users SET is_mfa_enabled=true WHERE id=$1`,
				"disabled":             `UPDATE users SET is_mfa_enabled=false WHERE id=$1`,
				"missing verifier":     `UPDATE users SET password_hash=NULL WHERE id=$1`,
				"unsupported verifier": `UPDATE users SET password_hash=$2 WHERE id=$1`,
			}[tc.mutation]
			if statement != "" {
				args := []any{a.user.ID}
				if tc.mutation == "unsupported verifier" {
					args = append(args, "not-an-admitted-verifier")
				}
				if _, err := f.pool.Exec(f.ctx, statement, args...); err != nil {
					t.Fatal(err)
				}
			}
			p := policy
			p.PasswordLoginEnabled = tc.enabled
			if tc.mutation == "no authority" {
				p.Usernames = nil
			}
			var beforeVersion, beforeEvents int64
			if err := f.pool.QueryRow(f.ctx, `SELECT auth_version,(SELECT count(*) FROM event_outbox WHERE admin_action) FROM users WHERE id=$1`, a.user.ID).Scan(&beforeVersion, &beforeEvents); err != nil {
				t.Fatal(err)
			}
			err := rbac.ProvisionRole(f.ctx, actions, uuid.New(), "spiffe://identity.test/role-protection", a.user.ID, "support", false, "test", p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("grant protection err=%v want=%v", err, tc.want)
			}
			var held bool
			var version, events, contexts int64
			if err := f.pool.QueryRow(f.ctx, `SELECT auth_version,
				EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1),
				(SELECT count(*) FROM event_outbox WHERE admin_action),
				(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1) FROM users WHERE id=$1`, a.user.ID).Scan(&version, &held, &events, &contexts); err != nil {
				t.Fatal(err)
			}
			if tc.want != nil {
				if held || version != beforeVersion || events != beforeEvents || contexts != 0 {
					t.Fatal("rejected protection predicate wrote role, authority or audit intent")
				}
			} else if !held || version != beforeVersion+1 || events != beforeEvents+1 || contexts != 1 {
				t.Fatal("eligible role grant did not atomically commit authority and audit intent")
			}
		})
	}
}

func TestAdminOperatorGrantVersusLastPasskeyRemovalIntegration(t *testing.T) {
	f, _ := newRoleProtectionFixture(t)
	policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}
	for _, ordering := range []string{"grant_first", "removal_first"} {
		t.Run(ordering, func(t *testing.T) {
			a := f.account(t, "dual", false)
			credentials, err := db.New(f.pool).ListWebauthnCredentialsByUser(f.ctx, a.user.ID)
			if err != nil || len(credentials) != 1 {
				t.Fatal("race requires exactly one persisted passkey")
			}
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			barrier := &credentialMutationBarrier{pool: f.pool, phase: "mutation_first", entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(barrier.release) })
			var workers sync.WaitGroup
			defer func() { release(); cancel(); workers.Wait() }()
			secondPID := make(chan uint32, 1)
			second := adminIntegrationBeginFunc(func(ctx context.Context) (pgx.Tx, error) {
				tx, err := f.pool.Begin(ctx)
				if err == nil {
					secondPID <- tx.Conn().PgConn().PID()
				}
				return tx, err
			})
			var grantTx adminaction.Beginner = barrier
			var removalTx webauthn.Transacter = second
			if ordering == "removal_first" {
				grantTx, removalTx = second, barrier
			}
			actions, err := adminaction.New(grantTx, f.cipher, "identity.audit.role-race", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			q := db.New(f.pool)
			keys, err := webauthn.New(webauthn.Config{RPID: "identity.example", RPDisplayName: "Identity", RPOrigins: []string{"https://identity.example"}, ChallengeTTL: time.Minute, MockChallengeKey: make([]byte, 32)}, q, q, webauthn.NewMemoryChallengeStore(), webauthn.WithTransacter(removalTx))
			if err != nil {
				t.Fatal(err)
			}
			keys.SetAccountPolicy(policy)
			current := session.Session{UserID: a.user.ID.String(), AuthVersion: a.user.AuthVersion, AuthVersionSet: true, Kind: session.KindAuthenticated}
			grant := func() error {
				return rbac.ProvisionRole(ctx, actions, uuid.New(), "spiffe://identity.test/role-race", a.user.ID, "support", false, "test", policy)
			}
			remove := func() error {
				return keys.DeleteCredential(session.WithSession(ctx, current), a.user.ID, credentials[0].ID)
			}
			first, next := grant, remove
			if ordering == "removal_first" {
				first, next = remove, grant
			}
			firstResult, secondResult := make(chan error, 1), make(chan error, 1)
			workers.Add(1)
			go func() { defer workers.Done(); firstResult <- first() }()
			select {
			case <-barrier.entered:
			case err := <-firstResult:
				t.Fatalf("first policy writer failed before commit barrier: %v", err)
			case <-ctx.Done():
				t.Fatal("first policy writer did not reach commit barrier")
			}
			workers.Add(1)
			go func() { defer workers.Done(); secondResult <- next() }()
			select {
			case pid := <-secondPID:
				waitCredentialRevocationLock(ctx, t, f.pool, pid)
			case <-ctx.Done():
				t.Fatal("second policy writer did not begin")
			}
			release()
			if err := <-firstResult; err != nil {
				t.Fatalf("first policy writer failed: %v", err)
			}
			want := webauthn.ErrAccountNotActive
			if ordering == "removal_first" {
				want = accountpolicy.ErrLastFactor
			}
			if err := <-secondResult; !errors.Is(err, want) {
				t.Fatalf("waiting policy writer err=%v want=%v", err, want)
			}
			var held bool
			var count, version, contexts int64
			if err := f.pool.QueryRow(ctx, `SELECT auth_version,
				EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1),
				(SELECT count(*) FROM webauthn_credentials WHERE user_id=$1),
				(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1) FROM users WHERE id=$1`, a.user.ID).Scan(&version, &held, &count, &contexts); err != nil {
				t.Fatal(err)
			}
			if version != a.user.AuthVersion+1 || ordering == "grant_first" && (!held || count != 1 || contexts != 1) || ordering == "removal_first" && (held || count != 0 || contexts != 0) {
				t.Fatal("role/removal race committed an unprotected grant or invalid authority transition")
			}
		})
	}
}

func newRoleProtectionFixture(t *testing.T) (*realLoginFixture, *adminaction.Service) {
	t.Helper()
	f := newRealLoginFixture(t, false, false)
	actions, err := adminaction.New(f.pool, f.cipher, "identity.audit.role-protection", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = op.Rollback(f.ctx) }()
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/role-policy"}
	policy := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "role-fixture-only", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry}
	if err := legalpolicy.Install(f.ctx, op, policy, "test"); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return f, actions
}
