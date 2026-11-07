package registration

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

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type candidateRows struct {
	pgx.Rows
	items []db.ListExpiredRegistrationAttemptsRow
	index int
}

func (r *candidateRows) Next() bool { r.index++; return r.index <= len(r.items) }
func (r *candidateRows) Scan(dest ...any) error {
	item := r.items[r.index-1]
	*dest[0].(*uuid.UUID) = item.ID
	*dest[1].(*string) = item.State
	*dest[2].(*uuid.NullUUID) = item.ResultUserID
	return nil
}
func (r *candidateRows) Err() error { return nil }
func (r *candidateRows) Close()     {}
func (tx *testTx) Query(ctx context.Context, sql string, _ ...any) (pgx.Rows, error) {
	name := queryName(sql)
	tx.ops = append(tx.ops, name)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := tx.failures[name]; err != nil {
		return nil, err
	}
	return &candidateRows{items: tx.candidates}, nil
}

func expiredCandidate(state string) db.ListExpiredRegistrationAttemptsRow {
	candidate := db.ListExpiredRegistrationAttemptsRow{ID: uuid.New(), State: state}
	if state == "completed" {
		candidate.ResultUserID = uuid.NullUUID{UUID: uuid.New(), Valid: true}
	}
	return candidate
}

func TestCleanupSubjectOrderHoldsContentionAndProgress(t *testing.T) {
	pending, held, contended, completed, failed := expiredCandidate("pending"), expiredCandidate("completed"), expiredCandidate("completed"), expiredCandidate("completed"), expiredCandidate("failed")
	list := &testTx{candidates: []db.ListExpiredRegistrationAttemptsRow{pending, held, contended, completed, failed}}
	pendingTx, heldTx, contendedTx, completedTx, failedTx := &testTx{affected: 1}, &testTx{held: true}, &testTx{failures: map[string]error{"subject_lock": &pgconn.PgError{Code: "55P03"}}}, &testTx{affected: 1}, &testTx{affected: 1}
	database := &testDatabase{txs: []*testTx{list, pendingTx, heldTx, contendedTx, completedTx, failedTx}}
	stats, err := Cleanup(context.Background(), database, 50)
	if err != nil || stats.Considered != 5 || stats.Deleted != 3 || stats.Held != 1 || stats.Contended != 1 {
		t.Fatalf("lost cleanup progress: %+v %v", stats, err)
	}
	if !reflect.DeepEqual(completedTx.ops, []string{"timeouts", "subject_lock", "RegistrationAttemptHeld", "DeleteExpiredRegistrationAttempt"}) {
		t.Fatalf("completed tuple/hold decision before subject lock: %v", completedTx.ops)
	}
	for _, tx := range []*testTx{pendingTx, failedTx} {
		if !reflect.DeepEqual(tx.ops, []string{"timeouts", "DeleteExpiredRegistrationAttempt"}) {
			t.Fatal("transient subject-free expiry acquired account locks")
		}
	}
	for _, tx := range database.txs {
		if !tx.rollbackBounded || tx.rollbacks != 1 || !tx.readCommitted {
			t.Fatal("cleanup transaction lifetime/isolation drift")
		}
	}
	if heldTx.commits != 0 || contendedTx.commits != 0 || list.commits != 0 {
		t.Fatal("held/contended/list transaction committed")
	}
}

func TestCleanupFailurePreservesCommitsAndSanitizes(t *testing.T) {
	private := errors.New("private-role-email-DSN")
	for _, stage := range []string{"list", "subject_lock", "RegistrationAttemptHeld", "DeleteExpiredRegistrationAttempt", "commit", "multiple deletes"} {
		t.Run(stage, func(t *testing.T) {
			list := &testTx{candidates: []db.ListExpiredRegistrationAttemptsRow{expiredCandidate("pending"), expiredCandidate("completed")}, failures: map[string]error{}}
			done, failed := &testTx{affected: 1}, &testTx{affected: 1, failures: map[string]error{}}
			want := int64(1)
			switch stage {
			case "list":
				list.failures["ListExpiredRegistrationAttempts"] = private
				want = 0
			case "multiple deletes":
				failed.affected = 2
			default:
				failed.failures[stage] = private
			}
			database := &testDatabase{txs: []*testTx{list, done, failed}}
			stats, err := Cleanup(context.Background(), database, 10)
			if stats.Deleted != want || err != ErrUnavailable || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsanitized failure or lost previous commits: %+v %v", stats, err)
			}
			if want == 1 && done.commits != 1 {
				t.Fatal("first receipt progress rolled back")
			}
			if database.begins == 3 && !failed.rollbackBounded {
				t.Fatal("failed cleanup rollback not detached and bounded")
			}
		})
	}
}

func TestCleanupInputCancellationAndLeastPrivileges(t *testing.T) {
	for _, batch := range []int32{-1, 0, 501} {
		database := &testDatabase{}
		if _, err := Cleanup(context.Background(), database, batch); err != ErrInvalid || database.begins != 0 {
			t.Fatal("invalid batch started SQL")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	database := &testDatabase{}
	if _, err := Cleanup(ctx, database, 1); err != ErrUnavailable || database.begins != 0 {
		t.Fatal("cancellation started SQL")
	}
	contract := CleanupPrivileges()
	if len(contract.Tables) != 2 || len(contract.Functions) != 0 || len(contract.Sequences) != 0 {
		t.Fatal("cleanup privilege surface widened")
	}
	for _, table := range contract.Tables {
		if table.Insert || table.Update || len(table.UpdateColumns) > 0 || table.Name != "public.registration_attempts" && table.Delete {
			t.Fatal("cleanup mutation grants widened")
		}
	}
	for _, column := range APIUpdateColumns() {
		if column == "expires_at" || column == "created_at" || column == "jkt" || column == "capability_hash" || column == "id" {
			t.Fatal("API can rewrite frozen authority")
		}
	}
}

type schemaDB struct {
	db.DBTX
	ready    bool
	err      error
	deadline time.Time
}

func (d *schemaDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	d.deadline, _ = ctx.Deadline()
	return booleanRow{d.ready, d.err}
}
func TestSchemaReadinessBoundedAndFailClosed(t *testing.T) {
	for _, d := range []*schemaDB{{}, {err: errors.New("private-diagnostics")}, {ready: true}} {
		err := CheckSchema(context.Background(), d)
		if d.ready {
			if err != nil {
				t.Fatal(err)
			}
		} else if err != ErrUnavailable {
			t.Fatal("schema readiness did not fail closed")
		}
		if d.deadline.IsZero() || time.Until(d.deadline) > 5*time.Second {
			t.Fatal("schema check lacks bound")
		}
	}
}
