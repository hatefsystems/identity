//go:build integration

package ledgerproof

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// These query tests use a newly created disposable database, not production
// maintenance privileges. Deliberately unconstrained fixtures model corrupt
// proof state without disabling any production trigger or editing migrations.
func proofDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		if os.Getenv("REQUIRE_RETENTION_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL required")
		}
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	name := "ledgerproof_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	_, err = pool.Exec(ctx, `
CREATE TABLE public.security_event_ledger (
 id uuid NOT NULL, account_ref uuid NOT NULL, identity_blind_index text,
 event_type text NOT NULL, client_ip text, ip_subnet text, user_agent text,
 device_fingerprint text, client_id text, scope text,
 timestamp timestamptz NOT NULL, retain_until timestamptz NOT NULL,
 chain_hash text NOT NULL, seq bigint PRIMARY KEY);
CREATE TABLE public.security_ledger_head (singleton boolean PRIMARY KEY, seq bigint NOT NULL, chain_hash text NOT NULL);
CREATE TABLE public.security_ledger_checkpoints (
 first_seq bigint PRIMARY KEY, last_seq bigint UNIQUE, predecessor_seq bigint,
 predecessor_hash text, terminal_hash text, erased_count bigint);`)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func persistedFixture() *memorySource {
	s := fixture(2, 8, 11, 18, 27)
	prev := audit.GenesisChainHash
	for i := range s.steps {
		r := s.steps[i].Record
		r.ID, r.AccountRef = uuid.NewString(), uuid.NewString()
		r.IdentityBlindIndex, r.IPSubnet, r.UserAgent = ptr("private-index"), ptr("192.0.2.0/24"), ptr("")
		r.DeviceFingerprint, r.ClientID, r.Scope = ptr("device"), ptr("client"), ptr("scope")
		s.steps[i].TerminalHash = audit.ChainHash(prev, audit.SerializeLedger(*r))
		prev, _ = audit.DecodeChainHash(s.steps[i].TerminalHash)
	}
	s.head.Hash = s.steps[len(s.steps)-1].TerminalHash
	return s
}

func replaceProof(t *testing.T, pool *pgxpool.Pool, s *memorySource) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "DELETE FROM public.security_event_ledger; DELETE FROM public.security_ledger_checkpoints; DELETE FROM public.security_ledger_head"); err != nil {
		t.Fatal(err)
	}
	for _, step := range s.steps {
		if step.Record == nil {
			_, err = tx.Exec(ctx, "INSERT INTO public.security_ledger_checkpoints VALUES($1,$2,$3,$4,$5,$6)", step.FirstSeq, step.LastSeq, step.PredecessorSeq, step.PredecessorHash, step.TerminalHash, step.ErasedCount)
		} else {
			r := step.Record
			_, err = tx.Exec(ctx, "INSERT INTO public.security_event_ledger VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", r.ID, r.AccountRef, r.IdentityBlindIndex, r.EventType, r.ClientIP, r.IPSubnet, r.UserAgent, r.DeviceFingerprint, r.ClientID, r.Scope, r.Timestamp, r.RetainUntil, step.TerminalHash, step.FirstSeq)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.headErr == nil {
		if _, err = tx.Exec(ctx, "INSERT INTO public.security_ledger_head VALUES(true,$1,$2)", s.head.Seq, s.head.Hash); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProofQueriesIntegration(t *testing.T) {
	pool := proofDatabase(t)
	for _, tc := range []struct {
		name, reason string
		mutate       func(*memorySource)
		verified     bool
	}{
		{"live", "", func(*memorySource) {}, true},
		{"prefix", "", func(s *memorySource) { s.erase(0, 1) }, true},
		{"interior and tail", "", func(s *memorySource) { s.erase(4, 4); s.erase(1, 2) }, true},
		{"all purged", "no_retained_records", func(s *memorySource) { s.erase(0, 4) }, false},
		{"missing head", "missing_head", func(s *memorySource) { s.headErr = ErrMissingHead }, false},
		{"lost prefix", "hash_mismatch", func(s *memorySource) { s.steps = s.steps[1:] }, false},
		{"lost tail", "head_mismatch", func(s *memorySource) { s.steps = s.steps[:4] }, false},
		{"wrong head", "head_mismatch", func(s *memorySource) { s.head.Hash = strings.Repeat("b", 64) }, false},
		{"malformed span", "invalid_checkpoint", func(s *memorySource) { s.erase(1, 2); s.steps[1].ErasedCount = 0 }, false},
		{"missing span predecessor", "checkpoint_link_mismatch", func(s *memorySource) { s.erase(1, 2); s.steps = s.steps[1:] }, false},
		{"wrong span predecessor", "checkpoint_link_mismatch", func(s *memorySource) { s.erase(1, 2); s.steps[1].PredecessorHash = strings.Repeat("a", 64) }, false},
		{"live inside span", "checkpoint_overlap", func(s *memorySource) { live := s.steps[1]; s.erase(1, 2); s.steps = append(s.steps, live) }, false},
		{"overlapping spans", "checkpoint_overlap", func(s *memorySource) {
			s.erase(1, 2)
			span := s.steps[1]
			span.FirstSeq = 9
			span.LastSeq = 17
			s.steps = append(s.steps, span)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := persistedFixture()
			tc.mutate(s)
			replaceProof(t, pool, s)
			r, err := VerifySnapshot(context.Background(), pool, Params{Limit: 20})
			if err != nil || r.Verified != tc.verified || (tc.reason != "" && (r.FailureReason == nil || *r.FailureReason != tc.reason)) {
				t.Fatalf("result=%+v err=%v want=%s", r, err, tc.reason)
			}
		})
	}
}

type concurrentProofPool struct {
	*pgxpool.Pool
	afterHead func()
}
type concurrentProofTx struct {
	pgx.Tx
	afterHead func()
}

func (p concurrentProofPool) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.Pool.BeginTx(ctx, opts)
	return &concurrentProofTx{Tx: tx, afterHead: p.afterHead}, err
}
func (tx *concurrentProofTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := tx.Tx.QueryRow(ctx, sql, args...)
	if strings.Contains(sql, "GetLedgerVerificationHead") && tx.afterHead != nil {
		change := tx.afterHead
		tx.afterHead = nil
		change()
	}
	return row
}

func TestProofSnapshotConcurrentCompactionIntegration(t *testing.T) {
	pool := proofDatabase(t)
	s := persistedFixture()
	replaceProof(t, pool, s)
	wrapped := concurrentProofPool{Pool: pool, afterHead: func() { s.erase(0, 4); replaceProof(t, pool, s) }}
	r, err := VerifySnapshot(context.Background(), wrapped, Params{Limit: 20})
	if err != nil || !r.Verified || r.Checked != 5 || r.PurgedCount != 0 || !r.Complete {
		t.Fatalf("mixed snapshots %+v %v", r, err)
	}
	r, err = VerifySnapshot(context.Background(), pool, Params{Limit: 20})
	if err != nil || r.Verified || r.Checked != 0 || r.PurgedCount != 5 || !r.Complete {
		t.Fatalf("new snapshot %+v %v", r, err)
	}
}

func TestProofCursorCompactionIntegration(t *testing.T) {
	pool := proofDatabase(t)
	s := persistedFixture()
	s.erase(0, 1)
	replaceProof(t, pool, s)
	r, err := VerifySnapshot(context.Background(), pool, Params{Limit: 1})
	if err != nil || r.Checked != 0 || r.PurgedCount != 2 || r.ProofSteps != 1 || r.NextAfterSeq == nil || *r.NextAfterSeq != 8 {
		t.Fatalf("unbounded page %+v %v", r, err)
	}
	p := Params{AfterSeq: *r.NextAfterSeq, ThroughSeq: r.ThroughSeq, HasThrough: true, PredecessorHash: *r.LastHash, Limit: 1}
	r, err = VerifySnapshot(context.Background(), pool, p)
	if err != nil || !r.Verified || r.Checked != 1 || r.NextAfterSeq == nil || *r.NextAfterSeq != 11 {
		t.Fatalf("exact terminal %+v %v", r, err)
	}
	s.erase(0, 1)
	replaceProof(t, pool, s)
	r, err = VerifySnapshot(context.Background(), pool, p)
	if err != nil || !r.RestartRequired || r.Verified || r.NextAfterSeq != nil || r.ThroughSeq != 27 {
		t.Fatalf("compacted cursor approximated %+v %v", r, err)
	}
}
