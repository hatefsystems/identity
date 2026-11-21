package rbac

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// ProvisionRole is exclusively for a trusted operator process with separately
// provisioned database credentials. Operator identity is attested by that
// process's launcher, never accepted from HTTP. Both grants and revocations
// serialize with moderation and commit their durable audit intent atomically.
// Without an explicit password-login policy, grants require a passkey.
func ProvisionRole(ctx context.Context, actions *adminaction.Service, operator uuid.UUID, identity string, target uuid.UUID, role string, revoke bool, environment string, policies ...accountpolicy.Policy) error {
	if len(policies) > 1 {
		return errors.New("rbac: at most one account policy required")
	}
	u, err := url.Parse(identity)
	if actions == nil || operator == uuid.Nil || target == uuid.Nil || err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(identity) > 255 || strings.ContainsAny(identity, " \t\r\n") {
		return errors.New("rbac: trusted operator identity and target required")
	}
	switch role {
	case "super_admin", "moderator", "support", "dpo":
	default:
		return errors.New("rbac: unsupported role")
	}
	op, err := actions.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = op.Rollback(context.WithoutCancel(ctx)) }()
	baseline, err := legalpolicy.LoadBaseline(ctx, op.Tx, uuid.Nil, environment)
	if err != nil {
		return err
	}
	if baseline.ContextRetention() != actions.ContextRetention() {
		return legalpolicy.ErrMismatch
	}
	policy := accountpolicy.Policy{}
	if !revoke && len(policies) != 0 {
		policy = policies[0]
	}
	authority, err := policy.Guard(ctx, op.Tx)
	if err != nil {
		return err
	}
	if err := pglock.LockAccount(ctx, op.Tx, target); err != nil {
		return err
	}
	user, err := op.Queries.GetUserForUpdateIncludingDeleted(ctx, target)
	if err != nil {
		return err
	}
	if !revoke {
		if user.Status != "active" || user.DeletedAt.Valid {
			return errors.New("rbac: grants require an active account")
		}
		state, err := policy.Read(ctx, op.Tx, user, authority)
		if err != nil {
			return err
		}
		state.Privileged = true
		if err := state.Check(); err != nil {
			return err
		}
	}
	had, err := op.Queries.UserHasRole(ctx, db.UserHasRoleParams{UserID: target, RoleID: role})
	if err != nil {
		return err
	}
	eventType := "admin.role.granted"
	if revoke {
		eventType = "admin.role.revoked"
		_, err = op.Queries.RemoveRoleFromUser(ctx, db.RemoveRoleFromUserParams{UserID: target, RoleID: role})
	} else {
		err = op.Queries.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: target, RoleID: role})
	}
	if err != nil {
		return err
	}
	if had == revoke {
		if _, err := op.Tx.Exec(ctx, `UPDATE users SET auth_version=auth_version+1, updated_at=NOW() WHERE id=$1`, target); err != nil {
			return err
		}
	}
	op.Event = audit.Event{EventType: eventType, ActorID: operator, ActorSPIFFEID: identity,
		ActionStatus: audit.StatusSuccess, SubjectID: &target,
		Payload: map[string]any{"role_id": role, "noop": had != revoke}}
	ctx = adminaction.WithContext(ctx, op)
	if err := adminaction.SetDetails(ctx, struct {
		Target uuid.UUID `json:"target"`
	}{target}); err != nil {
		return err
	}
	return op.Commit(ctx)
}
