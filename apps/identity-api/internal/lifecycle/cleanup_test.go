package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func expiredLifecycle(t *testing.T, legacy bool) db.EventOutbox {
	t.Helper()
	row := queuedLifecycle(t, legacy)
	row.PublishedAt = pgtype.Timestamptz{Time: time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond), Valid: true}
	return row
}

func cleanupList(rows ...db.EventOutbox) *runtimeTx {
	tx := runtimeBatch()
	tx.queries = map[string][]db.EventOutbox{"ListExpiredLifecycleEvents": rows}
	return tx
}

func cleanupRow(row db.EventOutbox) *runtimeTx {
	tx := runtimeBatch()
	tx.row = row
	return tx
}

func TestCleanupPublishedPreservesHeldAdminPendingAndInvalidRows(t *testing.T) {
	newRow, legacy, held := expiredLifecycle(t, false), expiredLifecycle(t, true), expiredLifecycle(t, false)
	unpublished, admin, unexpired := expiredLifecycle(t, false), expiredLifecycle(t, false), expiredLifecycle(t, false)
	unpublished.PublishedAt.Valid = false
	admin.AdminAction = true
	unexpired.PublishedAt.Time = time.Now().Add(time.Hour)
	poison := expiredLifecycle(t, true)
	poison.Payload = `{"user_id":"private-identifier","extra":"private-body"}`
	list := cleanupList(poison, newRow, legacy, held, unpublished, admin, unexpired)
	newTx, legacyTx, heldTx := cleanupRow(newRow), cleanupRow(legacy), cleanupRow(held)
	heldTx.affected["DeleteExpiredLifecycleEvent"] = 0
	b := &runtimeDB{txs: []*runtimeTx{list, newTx, legacyTx, heldTx}}
	n, err := CleanupPublished(context.Background(), b, 24*time.Hour, 500)
	if n != 2 || !errors.Is(err, ErrInvalidEvent) || b.calls != 4 || list.commits != 0 || list.rollbacks != 1 {
		t.Fatalf("cleanup lost boundaries or unrelated progress: %d %v", n, err)
	}
	for _, tx := range []*runtimeTx{newTx, legacyTx, heldTx} {
		var names []string
		for _, s := range tx.statements {
			names = append(names, s.name)
			if s.name == "account_lock" && (len(s.args) != 1 || s.args[0].(int64) >= 0) {
				t.Fatal("shared account advisory lock was not acquired")
			}
			if s.name == "DeleteExpiredLifecycleEvent" {
				_, accountID, err := decodeOutboxEvent(tx.row)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(s.args, []any{tx.row.ID, list.statements[1].args[0], accountID}) {
					t.Fatalf("delete did not bind the fresh row, cutoff and account: %#v", s.args)
				}
			}
		}
		if !reflect.DeepEqual(names, []string{"isolation", "account_lock", "GetExpiredLifecycleEventForUpdate", "DeleteExpiredLifecycleEvent"}) ||
			tx.commits != 1 || tx.rollbacks != 1 || !tx.readCommitted || !tx.rollbackActive || !tx.rollbackBounded {
			t.Fatalf("fresh hold/row decision did not follow account lock: %v", names)
		}
	}
}

func TestCleanupPublishedRechecksFreshLockedRow(t *testing.T) {
	for _, mode := range []string{"disappeared", "unpublished", "admin", "no longer expired", "account changed", "payload changed", "id changed"} {
		t.Run(mode, func(t *testing.T) {
			row := expiredLifecycle(t, false)
			tx := cleanupRow(row)
			wantInvalid := false
			switch mode {
			case "disappeared":
				tx.fail["GetExpiredLifecycleEventForUpdate"] = pgx.ErrNoRows
			case "unpublished":
				tx.row.PublishedAt.Valid = false
			case "admin":
				tx.row.AdminAction = true
			case "no longer expired":
				tx.row.PublishedAt.Time = time.Now().Add(time.Hour)
			case "account changed":
				tx.row.LifecycleUserID.UUID = uuid.New()
				tx.row.Payload = strings.ReplaceAll(row.Payload, row.LifecycleUserID.UUID.String(), tx.row.LifecycleUserID.UUID.String())
				wantInvalid = true
			case "payload changed":
				tx.row.Payload = `{"private":"secret"}`
				wantInvalid = true
			case "id changed":
				tx.row.ID = uuid.New()
				tx.row.Payload = strings.ReplaceAll(row.Payload, row.ID.String(), tx.row.ID.String())
				wantInvalid = true
			}
			b := &runtimeDB{txs: []*runtimeTx{cleanupList(row), tx}}
			n, err := CleanupPublished(context.Background(), b, 24*time.Hour, 50)
			if n != 0 || (err != nil) != wantInvalid || wantInvalid && !errors.Is(err, ErrInvalidEvent) ||
				runtimeHasStatement(tx, "DeleteExpiredLifecycleEvent") || tx.commits != 0 || !tx.rollbackActive || !tx.rollbackBounded {
				t.Fatalf("stale pre-lock snapshot used: %d %v", n, err)
			}
		})
	}
}

func TestCleanupPublishedFailurePrivacyAndPartialProgress(t *testing.T) {
	for _, mode := range []string{"begin", "list", "account_lock", "GetExpiredLifecycleEventForUpdate", "DeleteExpiredLifecycleEvent", "commit", "multiple deletes"} {
		t.Run(mode, func(t *testing.T) {
			first, second := expiredLifecycle(t, false), expiredLifecycle(t, false)
			list, done, failed := cleanupList(first, second), cleanupRow(first), cleanupRow(second)
			b := &runtimeDB{txs: []*runtimeTx{list, done, failed}}
			wantCount := int64(1)
			switch mode {
			case "begin":
				b.err, wantCount = errRuntimePrivate, 0
			case "list":
				list.fail["ListExpiredLifecycleEvents"], wantCount = errRuntimePrivate, 0
			case "commit":
				failed.commitErr = errRuntimePrivate
			case "multiple deletes":
				failed.affected["DeleteExpiredLifecycleEvent"] = 2
			default:
				failed.fail[mode] = errRuntimePrivate
			}
			n, err := CleanupPublished(context.Background(), b, 24*time.Hour, 50)
			if n != wantCount || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") {
				t.Fatalf("failure lost committed progress or disclosed details: %d %v", n, err)
			}
			if b.calls == 3 && (!failed.rollbackActive || !failed.rollbackBounded) {
				t.Fatal("failed transaction leaked its connection")
			}
		})
	}
}

func TestCleanupPublishedCancellationAndBounds(t *testing.T) {
	for _, stage := range []string{"before begin", "list", "account_lock", "GetExpiredLifecycleEventForUpdate", "DeleteExpiredLifecycleEvent"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			row := expiredLifecycle(t, false)
			list, tx := cleanupList(row), cleanupRow(row)
			switch stage {
			case "before begin":
				cancel()
			case "list":
				list.onStatement = func(name string) {
					if name == "ListExpiredLifecycleEvents" {
						cancel()
					}
				}
			default:
				tx.onStatement = func(name string) {
					if name == stage {
						cancel()
					}
				}
			}
			b := &runtimeDB{txs: []*runtimeTx{list, tx}}
			n, err := CleanupPublished(ctx, b, time.Hour, 50)
			if n != 0 || !errors.Is(err, context.Canceled) || tx.commits != 0 {
				t.Fatalf("cleanup ignored cancellation: %d %v", n, err)
			}
			if stage == "before begin" {
				if b.calls != 0 {
					t.Fatal("cleanup began after cancellation")
				}
				return
			}
			if !list.rollbackActive || !list.rollbackBounded || b.calls == 2 && (!tx.rollbackActive || !tx.rollbackBounded) {
				t.Fatal("cleanup cancellation did not release transactions with a bounded independent context")
			}
		})
	}
	for _, tc := range []struct {
		retention time.Duration
		batch     int32
	}{{0, 1}, {-1, 1}, {time.Nanosecond, 1}, {time.Hour, 0}, {time.Hour, -1}, {time.Hour, 501}} {
		b := &runtimeDB{}
		if _, err := CleanupPublished(context.Background(), b, tc.retention, tc.batch); err == nil || b.calls != 0 {
			t.Fatal("cleanup invalid bounds accepted")
		}
	}
	if _, err := CleanupPublished(context.Background(), nil, time.Hour, 1); err == nil {
		t.Fatal("nil cleanup database accepted")
	}
}
