package profile

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

var errPrivateDatabase = errors.New("database private-name private@example.invalid")

type testRow struct {
	values []any
	err    error
}

func (r testRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("unexpected test row shape")
	}
	for i, value := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

func rowValues(row db.GetUserProfileRow) []any {
	return []any{row.ID, row.Email, row.DisplayName, row.Status, row.LifecycleRevision, row.AuthVersion}
}

type testDatabase struct {
	db.DBTX
	row      db.GetUserProfileRow
	tx       *testTx
	readErr  error
	beginErr error
	reads    int
	begins   int
	options  pgx.TxOptions
}

func (d *testDatabase) QueryRow(ctx context.Context, _ string, args ...any) pgx.Row {
	d.reads++
	err := d.readErr
	if ctx.Err() != nil {
		err = ctx.Err()
	} else if args[0] != d.row.ID {
		err = pgx.ErrNoRows
	}
	return testRow{rowValues(d.row), err}
}

func (d *testDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	d.begins++
	d.options = options
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if d.beginErr != nil {
		return nil, d.beginErr
	}
	d.tx.row = d.row
	return d.tx, nil
}

type testTx struct {
	pgx.Tx
	row              db.GetUserProfileRow
	statements       []string
	fail             string
	lockChange       func(*db.GetUserProfileRow)
	updateCount      int64
	intents          []string
	commits          int
	rollbacks        int
	rollbackDetached bool
}

func statementName(sql string) string {
	if strings.Contains(sql, "pg_advisory_xact_lock") {
		return "account_lock"
	}
	return strings.Fields(sql)[2]
}

func (tx *testTx) statement(ctx context.Context, sql string) error {
	name := statementName(sql)
	tx.statements = append(tx.statements, name)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if tx.fail == name {
		return errPrivateDatabase
	}
	return nil
}

func (tx *testTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := tx.statement(ctx, sql); err != nil {
		return pgconn.CommandTag{}, err
	}
	switch statementName(sql) {
	case "UpdateUserDisplayName":
		if args[0] != tx.row.ID || args[2] != tx.row.AuthVersion || args[3] != tx.row.LifecycleRevision {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		tx.row.DisplayName = args[1].(string)
		return pgconn.NewCommandTag("UPDATE " + strconv.FormatInt(tx.updateCount, 10)), nil
	case "InsertLifecycleEvent":
		tx.intents = append(tx.intents, args[2].(string))
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (tx *testTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if err := tx.statement(ctx, sql); err != nil {
		return testRow{err: err}
	}
	if args[0] != tx.row.ID {
		return testRow{err: pgx.ErrNoRows}
	}
	if statementName(sql) == "AdvanceUserLifecycleRevision" {
		if tx.row.LifecycleRevision == 9223372036854775807 {
			return testRow{err: pgx.ErrNoRows}
		}
		tx.row.LifecycleRevision++
		return testRow{values: []any{tx.row.LifecycleRevision}}
	}
	if tx.lockChange != nil {
		tx.lockChange(&tx.row)
	}
	return testRow{values: rowValues(tx.row)}
}

func (tx *testTx) Commit(context.Context) error {
	tx.commits++
	if tx.fail == "commit" {
		return errPrivateDatabase
	}
	return nil
}

func (tx *testTx) Rollback(ctx context.Context) error {
	tx.rollbacks++
	deadline, ok := ctx.Deadline()
	tx.rollbackDetached = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second && ctx.Err() == nil
	return nil
}

func fixture(t *testing.T) (*Service, *testDatabase) {
	t.Helper()
	d := &testDatabase{row: db.GetUserProfileRow{ID: uuid.New(), Email: "private@example.invalid", DisplayName: "Old name",
		Status: "active", AuthVersion: 7, LifecycleRevision: 1<<53 + 1}, tx: &testTx{updateCount: 1}}
	s, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	return s, d
}

func TestProfileServiceReadsCurrentProjection(t *testing.T) {
	s, d := fixture(t)
	got, err := s.Get(context.Background(), d.row.ID, d.row.AuthVersion)
	if err != nil || got.ID != d.row.ID || got.DisplayName != "Old name" || got.LifecycleRevision != "9007199254740993" || got.Status != "active" || d.reads != 1 {
		t.Fatalf("profile snapshot mismatch: %v", err)
	}
	d.row.DisplayName, d.row.LifecycleRevision = "New name", d.row.LifecycleRevision+1
	got, err = s.Get(context.Background(), d.row.ID, d.row.AuthVersion)
	if err != nil || got.DisplayName != "New name" || got.LifecycleRevision != "9007199254740994" || d.reads != 2 {
		t.Fatal("profile values/revision were cached")
	}
}

func TestProfileServiceRejectsMissingInactiveAndStaleAuthority(t *testing.T) {
	for _, mode := range []string{"foreign", "missing", "suspended", "banned", "pending_verification", "pending_deletion", "stale version", "negative revision", "invalid stored name", "outage"} {
		t.Run(mode, func(t *testing.T) {
			s, d := fixture(t)
			id, version, want := d.row.ID, d.row.AuthVersion, ErrUnauthorized
			switch mode {
			case "foreign":
				id = uuid.New()
			case "missing":
				d.readErr = pgx.ErrNoRows
			case "outage":
				d.readErr, want = errPrivateDatabase, ErrUnavailable
			case "stale version":
				version--
			case "negative revision":
				d.row.LifecycleRevision, want = -1, ErrUnavailable
			case "invalid stored name":
				d.row.DisplayName, want = "name\n", ErrUnavailable
			default:
				d.row.Status = mode
			}
			if got, err := s.Get(context.Background(), id, version); got != (Profile{}) || !errors.Is(err, want) {
				t.Fatalf("rejection mismatch: %v", err)
			}
		})
	}
}

func TestProfileServiceUpdateTransactionAndExactRevision(t *testing.T) {
	s, d := fixture(t)
	result, err := s.Update(context.Background(), d.row.ID, d.row.AuthVersion, " \u00a0New name ", "9007199254740993")
	if err != nil || !result.Changed || result.Profile.DisplayName != "New name" || result.Profile.LifecycleRevision != "9007199254740994" {
		t.Fatalf("update mismatch: %v", err)
	}
	wantStatements := []string{"account_lock", "GetUserProfileForUpdate", "UpdateUserDisplayName", "AdvanceUserLifecycleRevision", "InsertLifecycleEvent"}
	if !reflect.DeepEqual(d.tx.statements, wantStatements) || d.options.IsoLevel != pgx.ReadCommitted || d.tx.commits != 1 ||
		d.tx.rollbacks != 1 || !d.tx.rollbackDetached || d.reads != 0 || d.tx.row.AuthVersion != d.row.AuthVersion || len(d.tx.intents) != 1 {
		t.Fatalf("update escaped ordered transaction: %+v", d.tx.statements)
	}
	event, err := lifecycle.UnmarshalEvent([]byte(d.tx.intents[0]))
	if err != nil || event.SchemaVersion != lifecycle.SchemaVersionV2 || event.GetRevision() != 1<<53+2 ||
		event.EventType != lifecycle.SubjectUpdated || !reflect.DeepEqual(event.ChangedFields, []string{"display_name"}) ||
		strings.Contains(d.tx.intents[0], "New name") || strings.Contains(d.tx.intents[0], d.row.Email) {
		t.Fatal("profile change lacked exact metadata-only v2 intent")
	}
}

func TestProfileServiceNoopAndConflict(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(strconv.FormatBool(stale), func(t *testing.T) {
			s, d := fixture(t)
			expected := d.row.LifecycleRevision
			if stale {
				expected--
			}
			result, err := s.Update(context.Background(), d.row.ID, d.row.AuthVersion, " Old name ", strconv.FormatInt(expected, 10))
			if stale && !errors.Is(err, ErrConflict) || !stale && err != nil || result.Changed || d.tx.commits != 0 ||
				!reflect.DeepEqual(d.tx.statements, []string{"account_lock", "GetUserProfileForUpdate"}) || d.tx.row != d.row {
				t.Fatalf("stale/noop edited state: %v", err)
			}
		})
	}
}

func TestProfileServiceRechecksLockedAuthority(t *testing.T) {
	for _, mode := range []string{"suspended", "banned", "auth version", "concurrent profile"} {
		t.Run(mode, func(t *testing.T) {
			s, d := fixture(t)
			d.tx.lockChange = func(row *db.GetUserProfileRow) {
				switch mode {
				case "auth version":
					row.AuthVersion++
				case "concurrent profile":
					row.LifecycleRevision++
				default:
					row.Status = mode
				}
			}
			want := ErrUnauthorized
			if mode == "concurrent profile" {
				want = ErrConflict
			}
			result, err := s.Update(context.Background(), d.row.ID, d.row.AuthVersion, "New name", "9007199254740993")
			if !errors.Is(err, want) || result != (UpdateResult{}) || d.tx.commits != 0 || len(d.tx.statements) != 2 {
				t.Fatalf("stale prelock authority accepted: %v", err)
			}
		})
	}
}

func TestProfileServiceDependencyFailuresRollbackAndRedact(t *testing.T) {
	for _, failure := range []string{"begin", "account_lock", "GetUserProfileForUpdate", "UpdateUserDisplayName", "AdvanceUserLifecycleRevision", "InsertLifecycleEvent", "commit", "wrong count", "overflow"} {
		t.Run(failure, func(t *testing.T) {
			s, d := fixture(t)
			d.tx.fail = failure
			if failure == "begin" {
				d.beginErr = errPrivateDatabase
			}
			if failure == "wrong count" {
				d.tx.updateCount = 0
			}
			if failure == "overflow" {
				d.row.LifecycleRevision = 9223372036854775807
			}
			result, err := s.Update(context.Background(), d.row.ID, d.row.AuthVersion, "New name", strconv.FormatInt(d.row.LifecycleRevision, 10))
			if !errors.Is(err, ErrUnavailable) || result != (UpdateResult{}) || strings.Contains(err.Error(), "private") ||
				failure != "begin" && (d.tx.rollbacks != 1 || !d.tx.rollbackDetached) || failure != "commit" && d.tx.commits != 0 {
				t.Fatalf("fault wasn't sanitized/rolled back: %v", err)
			}
		})
	}
}

func TestProfileServiceRejectsInputBeforeTransaction(t *testing.T) {
	for _, tc := range []struct{ name, revision string }{{"bad\n", "0"}, {strings.Repeat("x", 81), "0"}, {"name", "+0"}, {"name", ""}} {
		s, d := fixture(t)
		if _, err := s.Update(context.Background(), d.row.ID, d.row.AuthVersion, tc.name, tc.revision); err == nil || d.begins != 0 || d.reads != 0 {
			t.Fatal("invalid profile input reached database")
		}
	}
	if _, err := New(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil database accepted")
	}
	var typedNil *testDatabase
	if _, err := New(typedNil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("typed nil database accepted")
	}
}
