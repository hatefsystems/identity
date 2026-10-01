package pglock

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LockAccount serializes preservation and erasure even after users is deleted.
// Acquire subject locks in UUID order BEFORE user/hold/child row locks. The next
// deciding read must be a separate READ COMMITTED statement, not a CTE sharing
// the lock statement's pre-wait snapshot. Future ledger maintenance must follow
// this same protocol. Hash collisions only serialize unrelated accounts.
func LockAccount(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	if tx == nil || id == uuid.Nil {
		return errors.New("pglock: account transaction and ID required")
	}
	sum := sha256.Sum256(append([]byte("identity:account-lock:v1:"), id[:]...))
	// Reserve the negative keyspace, separate from the positive worker keys.
	key := int64(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
	key = -key - 1
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1::bigint)", key)
	return err
}
