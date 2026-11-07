package smsotp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type userTestDatabase struct {
	db.DBTX
	tx       *userTestTx
	beginErr error
}

func (d *userTestDatabase) BeginTx(_ context.Context, opt pgx.TxOptions) (pgx.Tx, error) {
	if opt.IsoLevel != pgx.ReadCommitted {
		return nil, errPrivate
	}
	return d.tx, d.beginErr
}

type userTestRow struct {
	values []any
	err    error
}

func (r userTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}

type userTestTx struct {
	pgx.Tx
	status           string
	version          int64
	deleted          pgtype.Timestamptz
	fail             string
	count            int64
	steps            []string
	commits          int
	rollbackDetached bool
}

func (tx *userTestTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	step := "lock"
	if strings.Contains(sql, "SetUserPhoneIfAuthorized") {
		step = "set"
	} else if strings.Contains(sql, "RemoveUserPhoneIfAuthorized") {
		step = "remove"
	}
	tx.steps = append(tx.steps, step)
	if tx.fail == step {
		return pgconn.CommandTag{}, errPrivate
	}
	if step == "set" && args[3] != tx.version || step == "remove" && args[1] != tx.version {
		return pgconn.CommandTag{}, errPrivate
	}
	return pgconn.NewCommandTag("UPDATE " + map[int64]string{0: "0", 1: "1", 2: "2"}[tx.count]), nil
}
func (tx *userTestTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	tx.steps = append(tx.steps, "read")
	if tx.fail == "read" {
		return userTestRow{err: errPrivate}
	}
	if tx.fail == "missing" {
		return userTestRow{err: pgx.ErrNoRows}
	}
	return userTestRow{values: []any{tx.status, tx.deleted, tx.version, int64(1)}}
}
func (tx *userTestTx) Commit(context.Context) error {
	tx.commits++
	if tx.fail == "commit" {
		return errPrivate
	}
	return nil
}
func (tx *userTestTx) Rollback(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	tx.rollbackDetached = ok && ctx.Err() == nil && time.Until(deadline) <= 5*time.Second
	return nil
}
func userStoreFixture(t *testing.T) (*PostgresUserStore, *userTestTx) {
	t.Helper()
	tx := &userTestTx{status: "active", version: 7, count: 1}
	s, err := NewUserStore(&userTestDatabase{tx: tx})
	if err != nil {
		t.Fatal(err)
	}
	return s, tx
}
func TestSMSPostgresStoreRequiresTransactionDatabase(t *testing.T) {
	if _, err := NewUserStore(nil); err == nil {
		t.Fatal("nil DB accepted")
	}
	var d *userTestDatabase
	if _, err := NewUserStore(d); err == nil {
		t.Fatal("typed nil DB accepted")
	}
}
func TestSMSPostgresStoreLocksBeforeFencedConditionalWrite(t *testing.T) {
	for _, remove := range []bool{false, true} {
		s, tx := userStoreFixture(t)
		id := uuid.New()
		var err error
		if remove {
			_, err = s.RemovePhoneIfCurrent(context.Background(), id, 7)
		} else {
			err = s.SetPhoneIfCurrent(context.Background(), id, 7, []byte("encrypted"), "index")
		}
		if err != nil || len(tx.steps) != 3 || tx.steps[0] != "lock" || tx.steps[1] != "read" || tx.commits != 1 || !tx.rollbackDetached {
			t.Fatalf("unfenced ordering: %v %+v", err, tx)
		}
	}
}
func TestSMSPostgresStoreStaleInactiveAndFailureHaveNoWrite(t *testing.T) {
	for _, failure := range []string{"stale", "inactive", "deleted", "missing", "lock", "read"} {
		t.Run(failure, func(t *testing.T) {
			s, tx := userStoreFixture(t)
			switch failure {
			case "stale":
				tx.version++
			case "inactive":
				tx.status = "suspended"
			case "deleted":
				tx.deleted.Valid = true
			default:
				tx.fail = failure
			}
			err := s.SetPhoneIfCurrent(context.Background(), uuid.New(), 7, []byte("encrypted"), "index")
			if err == nil || tx.commits != 0 || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe failure: %v", err)
			}
			for _, step := range tx.steps {
				if step == "set" || step == "remove" {
					t.Fatal("invalid authority wrote")
				}
			}
		})
	}
}
func TestSMSPostgresRemovalCountAndCommitFailures(t *testing.T) {
	s, tx := userStoreFixture(t)
	tx.count = 0
	changed, err := s.RemovePhoneIfCurrent(context.Background(), uuid.New(), 7)
	if changed || err != nil || tx.commits != 1 {
		t.Fatal("no-op removal claims event")
	}
	for _, failure := range []string{"set", "remove", "commit"} {
		s, tx := userStoreFixture(t)
		tx.fail = failure
		var changed bool
		var err error
		if failure == "set" {
			err = s.SetPhoneIfCurrent(context.Background(), uuid.New(), 7, nil, "")
		} else {
			changed, err = s.RemovePhoneIfCurrent(context.Background(), uuid.New(), 7)
		}
		if changed || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") {
			t.Fatal("failed/unknown commit claims change")
		}
	}
}
