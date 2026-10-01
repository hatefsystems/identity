package rbac

import (
	"context"
	"errors"
	"net/url"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// ProvisionRole is exclusively for a trusted operator process with separately
// provisioned database credentials. Operator identity is attested by that
// process's launcher, never accepted from HTTP. Both grants and revocations
// serialize with moderation and commit their durable audit intent atomically.
func ProvisionRole(ctx context.Context, actions *adminaction.Service, operator uuid.UUID, identity string, target uuid.UUID, role string, revoke bool) error {
	u, err := url.Parse(identity)
	if actions == nil || operator == uuid.Nil || target == uuid.Nil || err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(identity) > 255 {
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
	if err := pglock.LockAccount(ctx, op.Tx, target); err != nil {
		return err
	}
	user, err := op.Queries.GetUserForUpdateIncludingDeleted(ctx, target)
	if err != nil {
		return err
	}
	if !revoke {
		var hasPasskey bool
		if err := op.Tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=$1)`, target).Scan(&hasPasskey); err != nil {
			return err
		}
		if user.Status != "active" || user.DeletedAt.Valid || (!user.IsMfaEnabled && !hasPasskey) {
			return errors.New("rbac: grants require an active account with enrolled MFA")
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
