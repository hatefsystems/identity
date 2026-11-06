//go:build integration

package legalhold

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/receiptreconcile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/retention"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

func restoreDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, pool := disposableHoldDatabase(t)
	sqldb := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer func() {
		if err := sqldb.Close(); err != nil {
			t.Error("restore baseline migration connection cleanup failed")
		}
	}()
	if err := migrate.Up(ctx, sqldb); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

// This local drill certifies neither deployed backup/key recovery nor independent
// historical authenticity. Dumps, keys, rows and proofs stay in process memory.
func TestForwardRecoveryConsistentRestoreIntegration(t *testing.T) {
	for _, expanded := range []bool{false, true} {
		t.Run(map[bool]string{false: "baseline", true: "expanded_backfill"}[expanded], func(t *testing.T) {
			consistentRestoreIntegration(t, expanded)
		})
	}
}

func consistentRestoreIntegration(t *testing.T, expanded bool) {
	t.Helper()
	ctx, source := restoreDatabase(t)
	metadata := holdMigrationMetadata(ctx, t, source)
	var originalTable uint32
	if err := source.QueryRow(ctx, `SELECT 'public.legal_holds'::regclass::oid`).Scan(&originalTable); err != nil {
		t.Fatal(err)
	}
	if expanded {
		// Alter the real baseline table so workflow foreign keys survive backfill.
		if _, err := source.Exec(ctx, `ALTER TABLE public.legal_holds
DROP CONSTRAINT legal_holds_encrypted_or_purged,
ADD COLUMN reason TEXT,
ADD COLUMN requesting_authority VARCHAR(255),
ADD COLUMN legal_basis VARCHAR(255),`+expandedHoldChecks); err != nil {
			t.Fatal("expand baseline hold storage failed")
		}
	}
	svc, _ := testService(t)
	svc.store = db.New(source)
	var ids []uuid.UUID
	for _, kind := range []string{KindHold, KindPreservation} {
		if expanded {
			ids = append(ids, insertLegacyHold(ctx, t, source, false, kind))
			continue
		}
		details := Details{RecordID: uuid.New(), AccountRef: uuid.New(), Kind: kind,
			Reason: "fixture reason", RequestingAuthority: "fixture court", LegalBasis: "fixture basis"}
		blob, err := svc.seal(ctx, details)
		if err != nil {
			t.Fatal("encrypt baseline hold fixture failed")
		}
		if _, err := source.Exec(ctx, `INSERT INTO public.legal_holds(id,account_ref,applied_by,request_kind,details_encrypted,
applied_at,review_at) VALUES($1,$2,$3,$4,$5,'2026-01-01Z','2026-01-03Z')`,
			details.RecordID, details.AccountRef, uuid.New(), kind, blob); err != nil {
			t.Fatal("seed baseline encrypted hold failed")
		}
		ids = append(ids, details.RecordID)
	}
	converted := Details{RecordID: uuid.New(), AccountRef: uuid.New(), Kind: KindHold,
		Reason: "fixture reason", RequestingAuthority: "fixture court", LegalBasis: "fixture basis"}
	blob, err := svc.seal(ctx, converted)
	if err != nil {
		t.Fatal("encrypt keyed hold fixture failed")
	}
	if _, err := source.Exec(ctx, `INSERT INTO legal_holds(id,account_ref,applied_by,details_encrypted,idempotency_key,
is_active,released_at,released_by,applied_at,review_at) VALUES($1,$2,$3,$4,$5,false,'2026-01-02Z',$3,'2026-01-01Z','2026-01-03Z')`,
		converted.RecordID, converted.AccountRef, uuid.New(), blob, uuid.New()); err != nil {
		t.Fatal("seed encrypted keyed released hold failed")
	}
	ids = append(ids, converted.RecordID)
	seedRestoreChains(ctx, t, source)
	if expanded {
		before := restoreInventory(ctx, t, source)
		defer clearRestoreInventory(before)
		if err := contractHoldStorage(ctx, source); err == nil {
			t.Fatal("premature contraction accepted populated legacy holds")
		}
		afterRefusal := restoreInventory(ctx, t, source)
		compareRestoreInventory(t, before, afterRefusal)
		clearRestoreInventory(afterRefusal)
		compareRestoreInventory(t, metadata, holdMigrationMetadata(ctx, t, source))
		if err := svc.CheckCrypto(ctx); !errors.Is(err, ErrBackfillRequired) {
			t.Fatal("expanded baseline did not require backfill")
		}
		for range ids[:2] {
			if n, err := svc.Backfill(ctx, source, 1); err != nil || n != 1 {
				t.Fatal("bounded forward-recovery backfill failed")
			}
		}
	}
	for range 2 {
		if n, err := svc.Backfill(ctx, source, 1); err != nil || n != 0 {
			t.Fatal("completed or baseline backfill was not a repeatable no-op")
		}
	}
	for _, id := range ids {
		row, err := db.New(source).GetLegalHold(ctx, id)
		if err != nil {
			t.Fatal("forward-recovered hold read failed")
		}
		hold, err := svc.openHold(ctx, row)
		if err != nil || hold.Details.RecordID != id || hold.Details.AccountRef != row.AccountRef ||
			hold.Details.Kind != row.RequestKind || hold.Details.Reason != "fixture reason" ||
			hold.Details.RequestingAuthority != "fixture court" || hold.Details.LegalBasis != "fixture basis" {
			t.Fatal("forward-recovered encrypted details or bindings differ")
		}
	}
	if err := svc.CheckCrypto(ctx); err != nil {
		t.Fatal("forward-recovery crypto readiness failed")
	}
	if expanded {
		if err := contractHoldStorage(ctx, source); err != nil {
			t.Fatal("test storage contraction failed after verified backfill")
		}
	}
	var finalTable uint32
	if err := source.QueryRow(ctx, `SELECT 'public.legal_holds'::regclass::oid`).Scan(&finalTable); err != nil || finalTable != originalTable {
		t.Fatal("compatibility fixture replaced the baseline hold table")
	}
	compareRestoreInventory(t, metadata, holdMigrationMetadata(ctx, t, source))
	if n, err := svc.CleanupReleased(ctx, source, 1); err != nil || n != 1 {
		t.Fatal("released hold tombstone fixture failed")
	}
	expected := restoreInventory(ctx, t, source)
	defer clearRestoreInventory(expected)
	checkRestoredState(ctx, t, source, svc, ids)

	admin, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal("restore administration connection failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := admin.Close(cleanup); err != nil {
			t.Error("restore administration connection cleanup failed")
		}
	})
	cfg := source.Config()
	name := cfg.ConnConfig.Database
	source.Close() // No writers/goroutines are started by this fixture.
	// Terminate only run-owned sessions before snapshotting, then refuse
	// reconnections for the TEMPLATE copy below.
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE datname=$1`, name); err != nil {
		t.Fatal("stop run-owned source sessions failed")
	}

	// pg_dump owns a consistent snapshot. Missing clients are not a new CI
	// dependency: PostgreSQL's frozen TEMPLATE clone is exercised in every run.
	_, dumpErr := exec.LookPath("pg_dump")
	_, restoreErr := exec.LookPath("pg_restore")
	var dump []byte
	if dumpErr == nil && restoreErr == nil {
		var serverVersion int
		if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
			t.Fatal("read snapshot server version failed")
		}
		dumpVersion, err := exec.CommandContext(ctx, "pg_dump", "--version").Output()
		if err != nil {
			t.Fatal("inspect installed pg_dump failed")
		}
		restoreVersion, err := exec.CommandContext(ctx, "pg_restore", "--version").Output()
		if err != nil {
			t.Fatal("inspect installed pg_restore failed")
		}
		// Newer clients can emit unsupported server SET commands. They are not
		// usable restore tools for this drill; never mask an actual restore error.
		major := strconv.Itoa(serverVersion / 10000)
		if strings.Contains(string(dumpVersion), "(PostgreSQL) "+major+".") &&
			strings.Contains(string(restoreVersion), "(PostgreSQL) "+major+".") {
			command := exec.CommandContext(ctx, "pg_dump", "--format=custom")
			command.Env = restoreToolEnvironment(cfg.ConnConfig)
			dump, err = command.Output()
			if err != nil || len(dump) == 0 {
				t.Fatal("in-memory pg_dump failed")
			}
			defer clear(dump)
		} else {
			t.Log("PostgreSQL client/server majors differ: local frozen TEMPLATE clone drill only; not deployed backup restoration certification")
		}
	} else {
		t.Log("pg_dump/pg_restore unavailable: local frozen TEMPLATE clone drill only; not deployed backup restoration certification")
	}
	if _, err := admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{name}.Sanitize()+" ALLOW_CONNECTIONS false"); err != nil {
		t.Fatal("freeze run-owned source failed")
	}
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE datname=$1`, name); err != nil {
		t.Fatal("terminate remaining run-owned snapshot sessions failed")
	}
	var sessions int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=$1`, name).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("snapshot source still has sessions")
	}
	modes := []string{"local_clone", "local_clone_repeat"}
	if len(dump) != 0 {
		modes = append(modes, "pg_dump_pg_restore")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			restoredName := "hold_restore_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			quoted := pgx.Identifier{restoredName}.Sanitize()
			template := pgx.Identifier{name}.Sanitize()
			if mode == "pg_dump_pg_restore" {
				template = "template0"
			}
			if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE "+template); err != nil {
				t.Fatal("create run-owned restored database failed")
			}
			t.Logf("run-owned restored database: %s", restoredName)
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
					t.Errorf("drop run-owned restored database: %v", err)
				}
				var exists bool
				if err := admin.QueryRow(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, restoredName).Scan(&exists); err != nil || exists {
					t.Error("restored database cleanup not confirmed")
				}
			})
			restoredConfig := cfg.Copy()
			restoredConfig.ConnConfig.Database = restoredName
			if mode == "pg_dump_pg_restore" {
				command := exec.CommandContext(ctx, "pg_restore", "--exit-on-error", "--single-transaction", "--dbname=")
				command.Env = restoreToolEnvironment(restoredConfig.ConnConfig)
				command.Stdin = bytes.NewReader(dump)
				if err := command.Run(); err != nil {
					t.Fatal("in-memory pg_restore failed")
				}
			}
			restored, err := pgxpool.NewWithConfig(ctx, restoredConfig)
			if err != nil {
				t.Fatal("restored pool creation failed")
			}
			t.Cleanup(restored.Close)
			actual := restoreInventory(ctx, t, restored)
			defer clearRestoreInventory(actual)
			compareRestoreInventory(t, expected, actual)
			checkRestoredState(ctx, t, restored, svc, ids)
			t.Log("exact all-table and sequence data/digest, both full proofs, receipt reconciliation, crypto, replay and signer recovery checks passed; local drill only")
		})
	}
}

func seedRestoreChains(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	queries := db.New(pool)
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log_head VALUES(true,0,$1)`, audit.Genesis().Bytes()); err != nil {
		t.Fatal("seed audit genesis head failed")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO security_ledger_head VALUES(true,0,$1)`, audit.LedgerGenesis().Bytes()); err != nil {
		t.Fatal("seed both genesis heads failed")
	}
	subject := "identity.audit.restore"
	if _, err := pool.Exec(ctx, `INSERT INTO security_ledger_retention_settings VALUES(true,$1)`, subject); err != nil {
		t.Fatal("seed retention settings failed")
	}
	previous := audit.LedgerGenesis()
	at := audit.NormalizeChainTime(time.Now().Add(-2 * time.Hour))
	var candidates []retention.Candidate
	for i := 0; i < 4; i++ {
		retain := at.Add(time.Hour)
		if i >= 2 {
			retain = at.Add(24 * time.Hour)
		}
		client := "restore-fixture"
		record := audit.LedgerRecord{ID: uuid.NewString(), AccountRef: uuid.NewString(), EventType: audit.EventLoginSucceeded,
			Timestamp: at, RetainUntil: retain, ClientID: &client}
		leaf, err := audit.LeafLedger(record)
		if err != nil {
			t.Fatal("canonical ledger fixture failed")
		}
		previous = audit.ChainLedger(previous, leaf)
		seq, err := queries.InsertSecurityEventWithChain(ctx, db.InsertSecurityEventWithChainParams{
			EventID: uuid.MustParse(record.ID), AccountRef: uuid.MustParse(record.AccountRef), EventType: record.EventType,
			ClientID: record.ClientID, Timestamp: timestamptz(at), RetainUntil: timestamptz(retain),
			LeafHash: leaf.Bytes(), ChainHash: previous.Bytes()})
		if err != nil {
			t.Fatal("seed canonical ledger chain and body failed")
		}
		candidates = append(candidates, retention.Candidate{Seq: seq, AccountRef: uuid.MustParse(record.AccountRef), RetainUntil: retain})
	}
	if err := queries.AdvanceChainHead(ctx, db.AdvanceChainHeadParams{Which: "ledger", FirstSeq: candidates[0].Seq, LastSeq: candidates[3].Seq, NodeCount: 4}); err != nil {
		t.Fatal("advance populated ledger head failed")
	}
	purge, err := retention.NewPgStore(pool, subject)
	if err != nil {
		t.Fatal("create existing purge store failed")
	}
	boundary, err := purge.Capture(ctx)
	if err != nil {
		t.Fatal("capture purge fixture boundary failed")
	}
	for _, candidate := range candidates[:2] {
		if result, err := purge.Purge(ctx, boundary, []retention.Candidate{candidate}, false); err != nil || result.Deleted != 1 {
			t.Fatal("real atomic payload erasure, annotation and receipt intent failed")
		}
	}
	var wire []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM event_outbox ORDER BY id LIMIT 1`).Scan(&wire); err != nil {
		t.Fatal("read purge receipt fixture failed")
	}
	defer clear(wire)
	var receipt audit.Envelope
	if err := json.Unmarshal(wire, &receipt); err != nil {
		t.Fatal("decode existing receipt envelope failed")
	}
	previous = audit.Genesis()
	records := []audit.AuditRecord{
		{ID: uuid.NewString(), ActorID: uuid.NewString(), ActorSPIFFEID: audit.APIActorSPIFFEID, EventType: audit.EventLoginSucceeded,
			ActionStatus: audit.StatusSuccess, ClientIP: "203.0.113.9", UserAgent: "restore-fixture", Payload: `{"fixture":true}`, Timestamp: at},
		{ID: receipt.EventID.String(), ActorID: receipt.ActorID, ActorSPIFFEID: receipt.ActorSPIFFEID, EventType: receipt.EventType,
			ActionStatus: receipt.ActionStatus, ClientIP: receipt.ClientIP, UserAgent: receipt.UserAgent, Payload: receipt.Payload, Timestamp: receipt.OccurredAt},
	}
	var first, last int64
	for _, record := range records {
		leaf, err := audit.LeafAudit(record)
		if err != nil {
			t.Fatal("canonical audit fixture failed")
		}
		previous = audit.ChainAudit(previous, leaf)
		last, err = queries.InsertAuditLogWithChain(ctx, db.InsertAuditLogWithChainParams{EventID: uuid.MustParse(record.ID),
			ActorID: uuid.MustParse(record.ActorID), ActorSpiffeID: record.ActorSPIFFEID, EventType: record.EventType,
			ActionStatus: record.ActionStatus, ClientIp: record.ClientIP, UserAgent: record.UserAgent, Payload: record.Payload,
			Timestamp: timestamptz(record.Timestamp), LeafHash: leaf.Bytes(), ChainHash: previous.Bytes()})
		if err != nil {
			t.Fatal("seed canonical audit chain and body failed")
		}
		if first == 0 {
			first = last
		}
	}
	if err := queries.AdvanceChainHead(ctx, db.AdvanceChainHeadParams{Which: "audit", FirstSeq: first, LastSeq: last, NodeCount: 2}); err != nil {
		t.Fatal("advance populated audit head failed")
	}
}

func checkRestoredState(ctx context.Context, t *testing.T, pool *pgxpool.Pool, original *Service, ids []uuid.UUID) {
	t.Helper()
	svc := *original
	svc.store = db.New(pool)
	if err := svc.CheckCrypto(ctx); err != nil {
		t.Fatal("restored hold crypto readiness failed")
	}
	var workflowFKs, appliedBaseline int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint
WHERE confrelid='public.legal_holds'::regclass AND contype='f' AND convalidated
AND conrelid IN ('public.legal_case_holds'::regclass,'public.legal_hold_reviews'::regclass)`).Scan(&workflowFKs); err != nil || workflowFKs != 2 {
		t.Fatal("restored full baseline lost workflow hold foreign keys")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM public.identity_schema_version WHERE version_id=1 AND is_applied`).Scan(&appliedBaseline); err != nil || appliedBaseline != 1 {
		t.Fatal("restored full baseline metadata is missing")
	}
	if n, err := svc.Backfill(ctx, pool, 1); err != nil || n != 0 {
		t.Fatal("restored contracted backfill was not a no-op")
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public'
AND table_name='legal_holds' AND column_name IN ('reason','requesting_authority','legal_basis')`).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("restored schema retained legacy plaintext columns")
	}
	for i, id := range ids {
		row, err := db.New(pool).GetLegalHold(ctx, id)
		if err != nil || (i == 2 && !row.IdempotencyKey.Valid) {
			t.Fatal("restored hold replay metadata missing")
		}
		hold, err := svc.openHold(ctx, row)
		if err != nil || hold.DetailsPurged != (i == 2) {
			t.Fatal("restored encrypted hold or tombstone failed")
		}
		if i < 2 && (hold.Details.Reason != "fixture reason" || hold.Details.RequestingAuthority != "fixture court" || hold.Details.LegalBasis != "fixture basis") {
			t.Fatal("restored authenticated hold details differ")
		}
		if i == 2 {
			replayed, err := db.New(pool).GetLegalHoldByRequest(ctx, db.GetLegalHoldByRequestParams{
				AccountRef: row.AccountRef, RequestKind: row.RequestKind, IdempotencyKey: row.IdempotencyKey})
			if err != nil || replayed.ID != row.ID || replayed.IsActive || !replayed.DetailsPurgedAt.Valid ||
				!replayed.ReleasedAt.Time.Equal(row.ReleasedAt.Time) || !replayed.AppliedAt.Time.Equal(row.AppliedAt.Time) {
				t.Fatal("restored replay lookup lost tombstone binding or clocks")
			}
		}
	}
	for _, chain := range []ledgerproof.Chain{ledgerproof.ChainAudit, ledgerproof.ChainLedger} {
		result, err := ledgerproof.VerifySnapshot(ctx, pool, ledgerproof.Params{Chain: chain, Limit: 10})
		want, erased := 2, 0
		if chain == ledgerproof.ChainLedger {
			want, erased = 4, 2
		}
		if err != nil || !result.Verified || !result.Complete || result.Checked != want || result.ErasedChecked != erased {
			t.Fatal("restored full chain, retained leaves or erasure annotations failed")
		}
	}
	summary, err := receiptreconcile.ReconcileSnapshot(ctx, pool, receiptreconcile.Options{Limit: 10, ProofLimit: 10})
	if err != nil || summary.Chained != 1 || summary.RecordedPending != 1 || summary.Invalid != 0 || summary.MissingUnavailable != 0 ||
		summary.Incomplete != 0 || !summary.InventoryComplete || !summary.ProofVerified || !summary.ProofComplete {
		t.Fatal("restored receipt material did not reconcile as one chained and one pending")
	}
	opener, err := signer.NewPgBatchTxOpener(pool)
	if err != nil {
		t.Fatal("restored signer opener failed")
	}
	batch, err := opener.BeginBatch(ctx)
	if err != nil {
		t.Fatal("restored signer recovery transaction failed")
	}
	defer func() {
		if err := batch.Rollback(context.Background()); err != nil {
			t.Error("restored signer transaction cleanup failed")
		}
	}()
	auditHead, auditErr := batch.Store().GetAuditLogHead(ctx)
	ledgerHead, ledgerErr := batch.Store().GetSecurityLedgerHead(ctx)
	if auditErr != nil || ledgerErr != nil || !auditHead.StateValid || !ledgerHead.StateValid ||
		batch.ValidateLedgerState(ctx, ledgerHead.Seq) != nil {
		t.Fatal("restored signer refused consistent heads/ledger with pending receipt")
	}
}

func restoreInventory(ctx context.Context, t *testing.T, pool *pgxpool.Pool) map[string][]byte {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("open consistent inventory snapshot failed")
	}
	defer func() {
		if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("inventory snapshot cleanup failed")
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL timezone='UTC'; SET LOCAL statement_timeout='15s'`); err != nil {
		t.Fatal("inventory snapshot settings failed")
	}
	rows, err := tx.Query(ctx, `SELECT c.relname,c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN ('r','S') ORDER BY c.relname`)
	if err != nil {
		t.Fatal("inventory catalog failed")
	}
	type relation struct{ Name, Kind string }
	relations, err := pgx.CollectRows(rows, pgx.RowToStructByPos[relation])
	if err != nil {
		t.Fatal("inventory relations failed")
	}
	result := make(map[string][]byte, len(relations))
	for _, relation := range relations {
		query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text COLLATE "C"),'[]')::text FROM ` + pgx.Identifier{"public", relation.Name}.Sanitize() + ` r`
		if relation.Kind == "S" {
			query = `SELECT jsonb_build_object('last_value',last_value,'is_called',is_called)::text FROM ` + pgx.Identifier{"public", relation.Name}.Sanitize()
		}
		var data []byte
		if err := tx.QueryRow(ctx, query).Scan(&data); err != nil {
			t.Fatal("inventory exact relation data failed")
		}
		result[relation.Name] = data
	}
	return result
}

func compareRestoreInventory(t *testing.T, expected, actual map[string][]byte) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatal("restored relation inventory differs")
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	expectedHash, actualHash := sha256.New(), sha256.New()
	for _, key := range keys {
		if !bytes.Equal(expected[key], actual[key]) {
			t.Fatal("restored exact table or sequence data differs")
		}
		_, _ = expectedHash.Write([]byte(key + "\x00"))
		_, _ = expectedHash.Write(expected[key])
		_, _ = actualHash.Write([]byte(key + "\x00"))
		_, _ = actualHash.Write(actual[key])
	}
	if !bytes.Equal(expectedHash.Sum(nil), actualHash.Sum(nil)) {
		t.Fatal("restored database inventory digest differs")
	}
}

func clearRestoreInventory(inventory map[string][]byte) {
	for key, value := range inventory {
		clear(value)
		delete(inventory, key)
	}
}

func restoreToolEnvironment(cfg *pgx.ConnConfig) []string {
	// libpq reads the original connection options without credentials in argv.
	env := os.Environ()
	sslMode := "verify-full"
	if cfg.TLSConfig == nil {
		sslMode = "disable"
	}
	env = append(env, "PGHOST="+cfg.Host, "PGPORT="+strconv.Itoa(int(cfg.Port)), "PGUSER="+cfg.User, "PGPASSWORD="+cfg.Password,
		"PGSSLMODE="+sslMode,
		"PGDATABASE="+cfg.Database, "PGCONNECT_TIMEOUT=10")
	return env
}
