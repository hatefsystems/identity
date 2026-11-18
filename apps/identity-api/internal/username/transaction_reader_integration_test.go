//go:build integration

package username

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type countedReadDatabase struct {
	*pgxpool.Pool
	begins int
}

func (d *countedReadDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	d.begins++
	return d.Pool.BeginTx(ctx, options)
}

func TestPrivateTransactionScopedUsernameProjectionIntegration(t *testing.T) {
	f := usernameFixture(t)
	usernameActivateFixture(t, f)
	u := usernameUser(t, f)
	value := usernameChosen(t, f.normalizer, "\u0639\u0644\u06cc.\u0645\u0624\u0645\u0646\u06cc")
	if err := usernameAssign(f, f.store, u.ID, u.AuthVersion, value); err != nil {
		t.Fatal(err)
	}
	database := &countedReadDatabase{Pool: f.pool}
	store, err := NewStore(database, f.cipher, f.normalizer)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackUsername(tx)
	authority, err := store.GuardAuthority(f.ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(f.ctx, tx, u.ID); err != nil {
		t.Fatal(err)
	}
	result, err := store.GetInTx(f.ctx, tx, u.ID, u.AuthVersion, authority)
	if err != nil || result == nil || result.Display != value.Display() || database.begins != 0 {
		t.Fatal("transaction-scoped projection opened separate transaction or lost protected display")
	}
	wrong := authority
	wrong.Epoch++
	if _, err := store.GetInTx(f.ctx, tx, u.ID, u.AuthVersion, wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatal("transaction-scoped projection accepted substituted guard authority")
	}
	if _, err := store.GetInTx(f.ctx, tx, u.ID, u.AuthVersion+1, authority); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("transaction-scoped projection skipped captured account authority")
	}
	var absentStore *Store
	if _, err := absentStore.GetInTx(f.ctx, tx, u.ID, u.AuthVersion, GuardAuthority{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unconfigured projection fabricated absence for populated username")
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}
