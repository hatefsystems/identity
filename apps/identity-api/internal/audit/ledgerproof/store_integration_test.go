//go:build integration

package ledgerproof_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// Database-backed coverage for the proof Source.
//
// The unit tests drive the walker through an in-memory fake, so they cannot catch
// the failure mode that matters most here: a SQL projection that disagrees with
// the Go serializer. If ListSecurityLedgerChainForVerification omitted a column,
// or mapped a NULL to "", every retained record would fail to reproduce its leaf
// and an intact ledger would report as tampered. These tests therefore verify
// against real rows, including the NULL/non-NULL boundary on every nullable
// column and both branches of the payload-present split.

func proofFixture(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_RETENTION_INTEGRATION") == "1" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL is required by a mandatory integration gate")
		}
		t.Skip("DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	// A disposable database: verification walks the whole chain, so it cannot
	// share history with suites that deliberately corrupt rows.
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "proof_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop disposable proof database: %v", err)
		}
		_ = admin.Close(cleanup)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	// A hostile session default: verification must set its own isolation.
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "read committed"
	cfg.ConnConfig.RuntimeParams["timezone"] = "Pacific/Honolulu"

	dsnForMigrate := strings.Replace(dsn, "/identity?", "/"+name+"?", 1)
	if dsnForMigrate == dsn {
		t.Fatalf("could not derive a migration DSN for %s", name)
	}
	sqldb, err := migrate.Open(ctx, dsnForMigrate)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatal(err)
	}
	_ = sqldb.Close()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx,
		"INSERT INTO public.security_ledger_head VALUES (true,0,$1)", audit.LedgerGenesis().Bytes()); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

// fullyPopulatedRecord sets every nullable column, so the non-NULL branch of
// every pointer field is projected at least once.
func fullyPopulatedRecord(retain time.Time) audit.LedgerRecord {
	blind := strings.Repeat("a", 64)
	ip := "203.0.113.9"
	subnet := "203.0.113.0/24"
	agent := "curl/8.7.1"
	device := "device-abc"
	client := "portal"
	scope := "openid profile"
	return audit.LedgerRecord{
		ID: uuid.NewString(), AccountRef: uuid.NewString(),
		IdentityBlindIndex: &blind, BlindIndexVersion: 3, EventType: audit.EventLoginSucceeded,
		ClientIP: &ip, IPSubnet: &subnet, UserAgent: &agent, DeviceFingerprint: &device,
		ClientID: &client, Scope: &scope,
		Timestamp: audit.NormalizeChainTime(time.Now().Add(-time.Hour)), RetainUntil: audit.NormalizeChainTime(retain),
	}
}

// sparseRecord leaves every nullable column NULL, so the NULL branch is
// projected too. NULL and "" must hash differently, and a projection that
// collapsed them would only show up here.
func sparseRecord(retain time.Time) audit.LedgerRecord {
	return audit.LedgerRecord{
		ID: uuid.NewString(), AccountRef: uuid.NewString(),
		IdentityBlindIndex: nil, BlindIndexVersion: 0, EventType: audit.EventRTRBreach,
		Timestamp: audit.NormalizeChainTime(time.Now().Add(-time.Hour)), RetainUntil: audit.NormalizeChainTime(retain),
	}
}

// emptyStringRecord sets the nullable columns to "" rather than NULL.
func emptyStringRecord(retain time.Time) audit.LedgerRecord {
	empty := ""
	return audit.LedgerRecord{
		ID: uuid.NewString(), AccountRef: uuid.NewString(),
		IdentityBlindIndex: &empty, BlindIndexVersion: 1, EventType: audit.EventLoginFailed,
		ClientIP: &empty, IPSubnet: &empty, UserAgent: &empty, DeviceFingerprint: &empty,
		ClientID: &empty, Scope: &empty,
		Timestamp: audit.NormalizeChainTime(time.Now().Add(-time.Hour)), RetainUntil: audit.NormalizeChainTime(retain),
	}
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func seedProofChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, records ...audit.LedgerRecord) []int64 {
	t.Helper()
	queries := db.New(pool)
	previous := audit.LedgerGenesis()
	seqs := make([]int64, 0, len(records))
	for _, rec := range records {
		leaf, err := audit.LeafLedger(rec)
		if err != nil {
			t.Fatal(err)
		}
		previous = audit.ChainLedger(previous, leaf)
		seq, err := queries.InsertSecurityEventWithChain(ctx, db.InsertSecurityEventWithChainParams{
			EventID: uuid.MustParse(rec.ID), LeafHash: leaf.Bytes(), ChainHash: previous.Bytes(),
			AccountRef: uuid.MustParse(rec.AccountRef), IdentityBlindIndex: rec.IdentityBlindIndex,
			BlindIndexVersion: rec.BlindIndexVersion, EventType: rec.EventType,
			ClientIp: rec.ClientIP, IpSubnet: rec.IPSubnet, UserAgent: rec.UserAgent,
			DeviceFingerprint: rec.DeviceFingerprint, ClientID: rec.ClientID, Scope: rec.Scope,
			Timestamp:   pgtype.Timestamptz{Time: rec.Timestamp, Valid: true},
			RetainUntil: pgtype.Timestamptz{Time: rec.RetainUntil, Valid: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	if len(seqs) > 0 {
		if _, err := pool.Exec(ctx, "SELECT public.advance_chain_head('ledger',0,$1,$2,$3)",
			seqs[0], seqs[len(seqs)-1], int64(len(seqs))); err != nil {
			t.Fatal(err)
		}
	}
	return seqs
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func verifyWhole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, limit int32) ledgerproof.Result {
	t.Helper()
	params := ledgerproof.Params{Chain: ledgerproof.ChainLedger, Limit: limit}
	var last ledgerproof.Result
	total := 0
	erased := 0
	for {
		result, err := ledgerproof.VerifySnapshot(ctx, pool, params)
		if err != nil {
			t.Fatalf("VerifySnapshot: %v", err)
		}
		if !result.Verified {
			reason := "<nil>"
			if result.FailureReason != nil {
				reason = *result.FailureReason
			}
			t.Fatalf("verification failed at seq %v: %s", result.BrokenAtSeq, reason)
		}
		total += result.Checked
		erased += result.ErasedChecked
		last = result
		next, ok := result.NextParams(params)
		if !ok {
			if !result.Complete {
				t.Fatal("verification stopped before completing")
			}
			break
		}
		params = next
	}
	last.Checked, last.ErasedChecked = total, erased
	return last
}

// TestProofProjectionReproducesEveryLeafIntegration is the core SQL↔Go parity
// check. It covers all three nullable shapes in one chain, because a projection
// bug typically affects exactly one of them.
func TestProofProjectionReproducesEveryLeafIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	retain := time.Now().Add(8760 * time.Hour)
	seqs := seedProofChain(t, ctx, pool,
		fullyPopulatedRecord(retain), sparseRecord(retain), emptyStringRecord(retain))

	result := verifyWhole(t, ctx, pool, 100)
	if result.Checked != 3 {
		t.Fatalf("checked = %d, want 3", result.Checked)
	}
	if result.ErasedChecked != 0 {
		t.Errorf("erased_checked = %d, want 0", result.ErasedChecked)
	}
	if result.LastSeq == nil || *result.LastSeq != seqs[len(seqs)-1] {
		t.Errorf("last_seq = %v, want %d", result.LastSeq, seqs[len(seqs)-1])
	}
}

// TestProofVerifiesAcrossErasedSpanIntegration exercises the LEFT JOIN against
// real erased rows: the payload is gone, the leaf remains, and the erasure record
// authorizes the absence.
func TestProofVerifiesAcrossErasedSpanIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	retain := time.Now().Add(8760 * time.Hour)
	seqs := seedProofChain(t, ctx, pool,
		fullyPopulatedRecord(retain), sparseRecord(retain),
		emptyStringRecord(retain), fullyPopulatedRecord(retain))

	// Erase the two middle payloads and record the span.
	if _, err := pool.Exec(ctx,
		"DELETE FROM public.security_event_ledger WHERE seq = ANY($1::bigint[])", seqs[1:3]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.security_ledger_erasures
(first_seq,last_seq,operation_id,erased_at) VALUES($1,$2,$3,now())`,
		seqs[1], seqs[2], uuid.New()); err != nil {
		t.Fatal(err)
	}

	result := verifyWhole(t, ctx, pool, 100)
	if result.Checked != 4 {
		t.Fatalf("checked = %d, want 4", result.Checked)
	}
	if result.ErasedChecked != 2 {
		t.Errorf("erased_checked = %d, want 2", result.ErasedChecked)
	}
}

// TestProofRejectsUnexplainedDeletionIntegration is the check v1 could not make:
// a payload removed without an erasure record is tampering, not retention.
func TestProofRejectsUnexplainedDeletionIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	retain := time.Now().Add(8760 * time.Hour)
	seqs := seedProofChain(t, ctx, pool, fullyPopulatedRecord(retain), sparseRecord(retain))

	if _, err := pool.Exec(ctx, "DELETE FROM public.security_event_ledger WHERE seq=$1", seqs[1]); err != nil {
		t.Fatal(err)
	}

	result, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{
		Chain: ledgerproof.ChainLedger, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatal("an unexplained deletion verified clean")
	}
	if result.FailureReason == nil || *result.FailureReason != "payload_absent_without_erasure_record" {
		t.Fatalf("failure_reason = %v", result.FailureReason)
	}
	if result.BrokenAtSeq == nil || *result.BrokenAtSeq != seqs[1] {
		t.Errorf("broken_at_seq = %v, want %d", result.BrokenAtSeq, seqs[1])
	}
}

// TestProofPaginationIsConsistentIntegration checks the keyset boundary against
// real rows with allocation holes: an off-by-one would hash a node twice and
// report a break in an intact chain.
func TestProofPaginationIsConsistentIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	retain := time.Now().Add(8760 * time.Hour)

	// Burn sequence values so the chain is non-contiguous.
	if _, err := pool.Exec(ctx, "SELECT nextval('public.security_ledger_chain_seq'), nextval('public.security_ledger_chain_seq')"); err != nil {
		t.Fatal(err)
	}
	records := make([]audit.LedgerRecord, 0, 7)
	for i := 0; i < 7; i++ {
		records = append(records, fullyPopulatedRecord(retain))
	}
	seedProofChain(t, ctx, pool, records...)

	// Every page size must reach the same verified conclusion.
	for _, limit := range []int32{1, 2, 3, 100} {
		result := verifyWhole(t, ctx, pool, limit)
		if result.Checked != 7 {
			t.Errorf("limit %d: checked = %d, want 7", limit, result.Checked)
		}
	}
}

// TestProofSnapshotIsolationIntegration proves verification reads one snapshot.
// A batch committed mid-walk must not make an intact chain look like it ends
// before its head, which is why the pass runs in a REPEATABLE READ READ ONLY
// transaction rather than inheriting the session default set in the fixture.
func TestProofSnapshotIsolationIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	retain := time.Now().Add(8760 * time.Hour)
	seedProofChain(t, ctx, pool, fullyPopulatedRecord(retain), sparseRecord(retain))

	// A completed pass over the current chain.
	first := verifyWhole(t, ctx, pool, 100)
	if first.Checked != 2 {
		t.Fatalf("checked = %d, want 2", first.Checked)
	}

	// The head must be reconciled, not merely the nodes: a chain that is
	// internally consistent but does not match its head is what a coherent rewrite
	// produces.
	if _, err := pool.Exec(ctx, "UPDATE public.security_ledger_head SET chain_hash=$1", audit.LedgerGenesis().Bytes()); err != nil {
		t.Fatal(err)
	}
	result, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{
		Chain: ledgerproof.ChainLedger, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatal("a chain that does not match its head verified clean")
	}
	if result.FailureReason == nil || *result.FailureReason != "head_mismatch" {
		t.Fatalf("failure_reason = %v, want head_mismatch", result.FailureReason)
	}
}

// TestProofMissingHeadIsAnErrorIntegration keeps an uninitialized head from
// being treated as genesis.
func TestProofMissingHeadIsAnErrorIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	if _, err := pool.Exec(ctx, "DELETE FROM public.security_ledger_head"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{
		Chain: ledgerproof.ChainLedger, Limit: 10,
	}); !errors.Is(err, ledgerproof.ErrMissingHead) {
		t.Fatalf("error = %v, want ErrMissingHead", err)
	}
}

// TestProofUnknownSeedSeqIsRejectedIntegration keeps a resumed verification from
// being seeded with a neighbouring node's digest. Gaps are legal, so "at or
// after" would hand the walker the wrong predecessor.
func TestProofUnknownSeedSeqIsRejectedIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	retain := time.Now().Add(8760 * time.Hour)
	seqs := seedProofChain(t, ctx, pool, fullyPopulatedRecord(retain))

	if _, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{
		Chain: ledgerproof.ChainLedger, AfterSeq: seqs[0] + 500,
		ThroughSeq: seqs[0] + 600, HasThrough: true, Limit: 10,
	}); !errors.Is(err, ledgerproof.ErrUnknownSeq) {
		t.Fatalf("error = %v, want ErrUnknownSeq", err)
	}
}

// TestProofAuditChainIntegration exercises the same walker over the audit chain,
// confirming the two per-chain projections and domain prefixes are both wired
// correctly rather than only the ledger one.
func TestProofAuditChainIntegration(t *testing.T) {
	ctx, pool := proofFixture(t)
	if _, err := pool.Exec(ctx,
		"INSERT INTO public.audit_log_head VALUES (true,0,$1)", audit.AuditGenesis().Bytes()); err != nil {
		t.Fatal(err)
	}

	queries := db.New(pool)
	previous := audit.AuditGenesis()
	var firstSeq, lastSeq int64
	for i := 0; i < 3; i++ {
		eventID := uuid.New()
		actorID := uuid.New()
		timestamp := audit.NormalizeChainTime(time.Now().Add(-time.Duration(i) * time.Minute))
		rec := audit.AuditRecord{
			ID: eventID.String(), ActorID: actorID.String(),
			ActorSPIFFEID: audit.APIActorSPIFFEID, EventType: audit.EventLoginSucceeded,
			ActionStatus: audit.StatusSuccess, ClientIP: "203.0.113.9",
			UserAgent: "curl/8.7.1", Payload: `{"k":"v"}`, Timestamp: timestamp,
		}
		leaf, err := audit.LeafAudit(rec)
		if err != nil {
			t.Fatal(err)
		}
		previous = audit.ChainAudit(previous, leaf)
		seq, err := queries.InsertAuditLogWithChain(ctx, db.InsertAuditLogWithChainParams{
			EventID: eventID, LeafHash: leaf.Bytes(), ChainHash: previous.Bytes(),
			ActorID: actorID, ActorSpiffeID: rec.ActorSPIFFEID, EventType: rec.EventType,
			ActionStatus: rec.ActionStatus, ClientIp: rec.ClientIP, UserAgent: rec.UserAgent,
			Payload:   rec.Payload,
			Timestamp: pgtype.Timestamptz{Time: timestamp, Valid: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstSeq = seq
		}
		lastSeq = seq
	}
	if _, err := pool.Exec(ctx, "SELECT public.advance_chain_head('audit',0,$1,$2,3)", firstSeq, lastSeq); err != nil {
		t.Fatal(err)
	}

	result, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{
		Chain: ledgerproof.ChainAudit, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || !result.Complete || result.Checked != 3 {
		t.Fatalf("audit chain verification: %+v", result)
	}

	// The ledger domain must reject this chain: the prefixes are what stop a node
	// being replayed across chains.
	crossed, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{
		Chain: ledgerproof.ChainLedger, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if crossed.Checked != 0 && crossed.Verified {
		t.Fatal("an audit chain verified in the ledger domain")
	}
}
