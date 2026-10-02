package retention

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeLocker struct {
	acquired bool
	released bool
}

func (l *fakeLocker) TryLock(context.Context) (bool, func(), error) {
	return l.acquired, func() { l.released = true }, nil
}

type fakeStore struct {
	probeErr  error
	boundary  Boundary
	remaining []Candidate
	cursors   []int64
	limits    []int
	results   []BatchResult
	errors    []error
	calls     int
	dryRuns   []bool
	seen      []Boundary
}

func (s *fakeStore) Probe(context.Context) error               { return s.probeErr }
func (s *fakeStore) Capture(context.Context) (Boundary, error) { return s.boundary, nil }
func (s *fakeStore) Candidates(_ context.Context, b Boundary, cursor Candidate, limit int) ([]Candidate, error) {
	s.seen = append(s.seen, b)
	s.cursors = append(s.cursors, cursor.Seq)
	s.limits = append(s.limits, limit)
	n := min(limit, len(s.remaining))
	rows := s.remaining[:n]
	s.remaining = s.remaining[n:]
	return rows, nil
}
func (s *fakeStore) Purge(_ context.Context, b Boundary, _ []Candidate, dry bool) (BatchResult, error) {
	s.seen = append(s.seen, b)
	s.dryRuns = append(s.dryRuns, dry)
	i := s.calls
	s.calls++
	return s.results[i], s.errors[i]
}
func (*fakeStore) Backlog(context.Context, Boundary, int) (Backlog, error) { return Backlog{}, nil }

func TestRunBoundsCursorAndDryRun(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "dry_run"}[dry], func(t *testing.T) {
			account := uuid.New()
			store := &fakeStore{boundary: Boundary{Cutoff: time.Now().UTC(), ThroughSeq: 100},
				results: []BatchResult{{}, {Deleted: 1, Held: 1}, {Deleted: 1}},
				errors:  []error{ErrDeferred, nil, nil}}
			for seq := int64(1); seq <= 8; seq++ {
				store.remaining = append(store.remaining, Candidate{Seq: seq, AccountRef: account})
			}
			locker := &fakeLocker{acquired: true}
			var logs bytes.Buffer
			worker, err := New(Config{BatchSize: 2, MaxRows: 5, Timeout: time.Minute, DryRun: dry}, store, locker, slog.New(slog.NewJSONHandler(&logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			stats, err := worker.RunOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if stats.Considered != 5 || stats.Deferred != 2 || stats.Held != 1 || !locker.released {
				t.Fatalf("incorrect accounting: %+v", stats)
			}
			if dry && (stats.Deleted != 0 || stats.WouldDelete != 2) || !dry && (stats.Deleted != 2 || stats.WouldDelete != 0) {
				t.Fatalf("dry-run accounting: %+v", stats)
			}
			if store.cursors[1] != 2 || store.cursors[2] != 4 || store.limits[2] != 1 {
				t.Fatalf("cursor did not advance over deferred work: %v %v", store.cursors, store.limits)
			}
			for _, b := range store.seen {
				if b != store.boundary {
					t.Fatal("run boundary changed")
				}
			}
			if strings.Contains(logs.String(), account.String()) {
				t.Fatal("account leaked to log")
			}
		})
	}
}

func TestUncertainCommitIsNotRetriedOrCounted(t *testing.T) {
	store := &fakeStore{remaining: []Candidate{{Seq: 1}, {Seq: 2}},
		results: []BatchResult{{Deleted: 2}}, errors: []error{ErrUncertain}}
	worker, _ := New(Config{BatchSize: 2, MaxRows: 4, Timeout: time.Minute}, store, &fakeLocker{acquired: true}, nil)
	stats, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrUncertain) || stats.Deleted != 0 || stats.Uncertain != 2 || stats.Failed != 0 || store.calls != 1 {
		t.Fatalf("uncertain commit misreported: %+v, %v", stats, err)
	}
}

func TestOverlapAndProbeFailure(t *testing.T) {
	for _, probeErr := range []error{nil, ErrPrivilege} {
		store := &fakeStore{probeErr: probeErr}
		worker, _ := New(Config{BatchSize: 1, MaxRows: 1, Timeout: time.Minute}, store, &fakeLocker{}, nil)
		stats, err := worker.RunOnce(context.Background())
		if !errors.Is(err, probeErr) || stats.Overlap != (probeErr == nil) || store.calls != 0 {
			t.Fatalf("unexpected overlap/probe outcome: %+v, %v", stats, err)
		}
	}
}

func TestCancelledRunNeverBeginsBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeStore{remaining: []Candidate{{Seq: 1}}}
	locker := &fakeLocker{acquired: true}
	worker, _ := New(Config{BatchSize: 1, MaxRows: 1, Timeout: time.Second}, store, locker, nil)
	stats, err := worker.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) || stats.Deleted != 0 || store.calls != 0 || !locker.released {
		t.Fatalf("cancellation not honored: %+v, %v", stats, err)
	}
}

func TestDatabaseErrorsAreSanitized(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"55P03", ErrDeferred}, {"57014", ErrDeferred}, {"40P01", ErrDeferred},
		{"42501", ErrPrivilege}, {"25001", ErrPrivilege}, {"42P01", ErrPrivilege},
		{"23000", ErrIntegrity}, {"23514", ErrIntegrity}, {"P0002", ErrIntegrity},
		{"08006", ErrDatabase},
	} {
		err := classify(&pgconn.PgError{Code: tc.code, Message: "secret account reference", Detail: "private event body"})
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe error mapping for %s: %v", tc.code, err)
		}
	}
}

func TestCommitRequiresAnUnambiguousRollbackResponse(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want error
	}{
		{pgx.ErrTxCommitRollback, ErrDatabase},
		{&pgconn.PgError{Severity: "ERROR", Code: "23514"}, ErrIntegrity},
		{&pgconn.PgError{Severity: "FATAL", Code: "57P01"}, ErrUncertain},
		{context.DeadlineExceeded, ErrUncertain},
		{errors.New("connection lost after COMMIT"), ErrUncertain},
	} {
		if err := commitFailure(tc.err); !errors.Is(err, tc.want) {
			t.Fatalf("commit outcome %v: got %v, want %v", tc.err, err, tc.want)
		}
	}
}
