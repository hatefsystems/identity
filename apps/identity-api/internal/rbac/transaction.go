package rbac

import (
	"context"
	"errors"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// ErrForbidden deliberately hides which account or permission check failed.
var ErrForbidden = errors.New("rbac: forbidden")

// LockAuthorized rechecks a mutation's actor after taking subject advisory locks
// and user row locks in deterministic order. Missing targets are allowed for
// post-deletion legal work; callers decide their own target existence policy.
// Operator role changes must take these same locks before changing memberships.
func LockAuthorized(ctx context.Context, tx pgx.Tx, actor uuid.UUID, targets []uuid.UUID, permission string, authVersion int64) error {
	ids := append([]uuid.UUID{actor}, targets...)
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	unique := ids[:0]
	for _, id := range ids {
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	for _, id := range unique {
		if err := pglock.LockAccount(ctx, tx, id); err != nil {
			return err
		}
	}
	q := db.New(tx)
	for _, id := range unique {
		u, err := q.GetUserForUpdateIncludingDeleted(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) && id != actor {
			continue
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if id == actor && (u.Status != "active" || u.DeletedAt.Valid || u.AuthVersion != authVersion) {
			return ErrForbidden
		}
	}
	allowed, err := q.UserHasPermission(ctx, db.UserHasPermissionParams{UserID: actor, PermissionID: permission})
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}
