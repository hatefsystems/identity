//go:build integration

package retention

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func TestWorkerProbeIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	var login, session, isolation string
	if err := f.worker.QueryRow(f.ctx, "SELECT current_user,session_user,current_setting('default_transaction_isolation')").Scan(&login, &session, &isolation); err != nil {
		t.Fatal(err)
	}
	if login != "identity_ledger_purge" || session != login || isolation != "repeatable read" {
		t.Fatalf("not a real restricted worker login with RR default: %s/%s/%s", login, session, isolation)
	}
	privileged, err := NewPgStore(f.admin, f.subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := privileged.Probe(f.ctx); !errors.Is(err, ErrPrivilege) {
		t.Fatalf("privileged connection accepted: %v", err)
	}
	wrongSubject, err := NewPgStore(f.worker, "identity.audit.wrong")
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongSubject.Probe(f.ctx); !errors.Is(err, ErrPrivilege) {
		t.Fatalf("wrong subject accepted: %v", err)
	}
	// Changes here are database-local and restored before the next case. Never
	// change cluster-global role attributes/memberships while sibling suites run.
	for _, tc := range []struct {
		name, change, restore string
		want                  error
	}{
		{"missing settings", "DELETE FROM public.security_ledger_retention_settings", "INSERT INTO public.security_ledger_retention_settings VALUES(true,'" + f.subject + "')", ErrPrivilege},
		{"missing head", "DELETE FROM public.security_ledger_head", "INSERT INTO public.security_ledger_head VALUES(true,0,repeat('0',64))", ErrIntegrity},
		{"inconsistent head", "UPDATE public.security_ledger_head SET seq=9,chain_hash=repeat('a',64)", "UPDATE public.security_ledger_head SET seq=0,chain_hash=repeat('0',64)", ErrIntegrity},
		{"public execute", "GRANT EXECUTE ON FUNCTION " + integrationPurgeRoutine + " TO PUBLIC", "REVOKE EXECUTE ON FUNCTION " + integrationPurgeRoutine + " FROM PUBLIC", ErrPrivilege},
		{"missing execute", "REVOKE EXECUTE ON FUNCTION " + integrationPurgeRoutine + " FROM identity_ledger_purge", "GRANT EXECUTE ON FUNCTION " + integrationPurgeRoutine + " TO identity_ledger_purge", ErrPrivilege},
		{"unsafe search path", "ALTER FUNCTION " + integrationPurgeRoutine + " SET search_path=public,pg_catalog", "ALTER FUNCTION " + integrationPurgeRoutine + " SET search_path=pg_catalog,pg_temp", ErrPrivilege},
		{"invoker routine", "ALTER FUNCTION " + integrationPurgeRoutine + " SECURITY INVOKER", "ALTER FUNCTION " + integrationPurgeRoutine + " SECURITY DEFINER", ErrPrivilege},
		{"login owner", "ALTER FUNCTION " + integrationPurgeRoutine + " OWNER TO CURRENT_USER", "ALTER FUNCTION " + integrationPurgeRoutine + " OWNER TO identity_ledger_maintenance_owner", ErrPrivilege},
		{"worker table owner", "ALTER TABLE public.security_ledger_retention_settings OWNER TO identity_ledger_purge", "ALTER TABLE public.security_ledger_retention_settings OWNER TO CURRENT_USER; GRANT SELECT ON public.security_ledger_retention_settings TO identity_ledger_purge", ErrPrivilege},
		{"maintenance table owner", "ALTER TABLE public.security_ledger_retention_settings OWNER TO identity_ledger_maintenance_owner", "ALTER TABLE public.security_ledger_retention_settings OWNER TO CURRENT_USER; GRANT SELECT ON public.security_ledger_retention_settings TO identity_ledger_maintenance_owner", ErrPrivilege},
		{"schema creation", "GRANT CREATE ON SCHEMA public TO identity_ledger_purge", "REVOKE CREATE ON SCHEMA public FROM identity_ledger_purge", ErrPrivilege},
		{"database creation", "GRANT CREATE ON DATABASE worker_integration_agent TO identity_ledger_purge", "REVOKE CREATE ON DATABASE worker_integration_agent FROM identity_ledger_purge", ErrPrivilege},
		{"head advancement", "GRANT EXECUTE ON FUNCTION public.advance_security_ledger_head(bigint,uuid) TO identity_ledger_purge", "REVOKE EXECUTE ON FUNCTION public.advance_security_ledger_head(bigint,uuid) FROM identity_ledger_purge", ErrPrivilege},
		{"direct outbox write", "GRANT INSERT ON public.event_outbox TO identity_ledger_purge", "REVOKE INSERT ON public.event_outbox FROM identity_ledger_purge", ErrPrivilege},
		{"column outbox write", "GRANT INSERT(id,subject,payload) ON public.event_outbox TO identity_ledger_purge", "REVOKE INSERT(id,subject,payload) ON public.event_outbox FROM identity_ledger_purge", ErrPrivilege},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workerExec(t, f.ctx, f.admin, tc.change)
			t.Cleanup(func() { workerExec(t, f.ctx, f.admin, tc.restore) })
			if err := f.store.Probe(f.ctx); !errors.Is(err, tc.want) {
				t.Fatalf("probe=%v, want %v", err, tc.want)
			}
		})
	}
	if err := f.store.Probe(f.ctx); err != nil {
		t.Fatalf("restored provisioning rejected: %v", err)
	}
}

func TestWorkerDryRunAndBoundedKeysetIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	expired := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Microsecond)
	account, held := uuid.New(), uuid.New()
	var records []audit.LedgerRecord
	// The oldest account is held and must not consume the considered-row budget.
	for range 8 {
		records = append(records, workerLedgerRecord(held, expired.Add(-time.Hour)))
	}
	for range 11 {
		records = append(records, workerLedgerRecord(account, expired))
	}
	seeded := f.seed(t, records...)
	f.hold(t, f.admin, held)
	before := f.boundary(t)
	stats := f.run(t, 2, 5, true)
	if stats.Considered != 5 || stats.WouldDelete != 5 || stats.Deleted != 0 || stats.Held != 0 || !stats.Backlog.Capped || stats.Backlog.Count != 5 {
		t.Fatalf("dry-run bounds/fairness: %+v", stats)
	}
	f.assertState(t, 19, 0, 0)
	stats = f.run(t, 2, 5, false)
	if stats.Considered != 5 || stats.Deleted != 5 || stats.WouldDelete != 0 || stats.Held != 0 {
		t.Fatalf("first bounded run: %+v", stats)
	}
	f.assertState(t, 14, 1, 3)
	// Equal expirations require the sequence tie-breaker, even while rows vanish.
	for _, row := range seeded[8:13] {
		if f.count(t, "SELECT count(*) FROM public.security_event_ledger WHERE seq=$1", row.Seq) != 0 {
			t.Fatalf("keyset skipped the oldest eligible sequence %d", row.Seq)
		}
	}
	stats = f.run(t, 2, 20, false)
	if stats.Deleted != 6 || stats.Considered != 6 || stats.Backlog.Count != 0 || stats.Backlog.Capped {
		t.Fatalf("continuation run: %+v", stats)
	}
	f.assertState(t, 8, 1, 6)
	after := f.boundary(t)
	if after.ThroughSeq != before.ThroughSeq {
		t.Fatal("tail deletion rewound durable head")
	}
	var first, last, predecessor, erased int64
	if err := f.admin.QueryRow(f.ctx, "SELECT first_seq,last_seq,predecessor_seq,erased_count FROM public.security_ledger_checkpoints").Scan(&first, &last, &predecessor, &erased); err != nil {
		t.Fatal(err)
	}
	if first != seeded[8].Seq || last != seeded[18].Seq || predecessor != seeded[7].Seq || erased != 11 {
		t.Fatalf("checkpoint crossed held island or counted allocation gaps: %d/%d/%d/%d", first, last, predecessor, erased)
	}
}

func TestWorkerRetentionBoundariesHoldsAndDeletedAccountsIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	live, deleted, held := uuid.New(), uuid.New(), uuid.New()
	workerExec(t, f.ctx, f.admin, "INSERT INTO public.users(id,email) VALUES($1,'live@example.test'),($2,'deleted@example.test')", live, deleted)
	records := []audit.LedgerRecord{
		workerLedgerRecord(live, cutoff.Add(-time.Microsecond)),
		workerLedgerRecord(live, cutoff),
		workerLedgerRecord(deleted, cutoff.Add(-2*time.Hour)),
		workerLedgerRecord(held, cutoff.Add(-time.Hour)),
		workerLedgerRecord(live, cutoff.Add(time.Microsecond)),
		workerLedgerRecord(deleted, cutoff.Add(-time.Microsecond)),
	}
	seeded := f.seed(t, records...)
	workerExec(t, f.ctx, f.admin, "DELETE FROM public.users WHERE id=$1", deleted)
	firstHold := f.hold(t, f.admin, held)
	lastHold := f.hold(t, f.admin, held)
	b := Boundary{Cutoff: cutoff, ThroughSeq: seeded[len(seeded)-1].Seq}
	candidates, err := f.store.Candidates(f.ctx, b, Candidate{}, 50)
	if err != nil || len(candidates) != 3 || candidates[0].Seq != seeded[2].Seq || candidates[1].Seq != seeded[0].Seq || candidates[2].Seq != seeded[5].Seq {
		t.Fatalf("strict cutoff, persisted expiration order and held prefilter: %+v / %v", candidates, err)
	}
	result, err := f.store.Purge(f.ctx, b, candidates, false)
	if err != nil || result.Deleted != 3 || result.Held != 0 {
		t.Fatalf("boundary purge: %+v / %v", result, err)
	}
	f.assertState(t, 3, 3, 1)
	if f.count(t, "SELECT count(*) FROM public.users WHERE id=$1", live) != 1 {
		t.Fatal("Class A live account was deleted")
	}
	for _, index := range []int{1, 3, 4} {
		var actual []byte
		if err := f.admin.QueryRow(f.ctx, "SELECT public.security_ledger_canonical_body(l) FROM public.security_event_ledger l WHERE seq=$1", seeded[index].Seq).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, audit.SerializeLedger(records[index])) {
			t.Fatal("retained signed timestamps/body were rewritten")
		}
	}
	workerExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false WHERE id=$1", firstHold)
	candidates, err = f.store.Candidates(f.ctx, b, Candidate{}, 50)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("independent active hold lost: %+v / %v", candidates, err)
	}
	workerExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false WHERE id=$1", lastHold)
	candidates, err = f.store.Candidates(f.ctx, b, Candidate{}, 50)
	if err != nil || len(candidates) != 1 || candidates[0].Seq != seeded[3].Seq {
		t.Fatalf("last release restarted retention or required users row: %+v / %v", candidates, err)
	}
	result, err = f.store.Purge(f.ctx, b, candidates, false)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("last release purge: %+v / %v", result, err)
	}
	f.assertState(t, 2, 3, 2)
}

func TestWorkerCanonicalPreflightAndFixedHighwaterIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	expired := time.Date(2020, 2, 29, 12, 34, 56, 123400000, time.FixedZone("fixture", 3*3600+1800))
	nilFields := workerLedgerRecord(uuid.New(), expired)
	emptyFields := workerLedgerRecord(uuid.New(), expired.Add(time.Microsecond))
	empty := ""
	emptyFields.IdentityBlindIndex, emptyFields.ClientIP, emptyFields.IPSubnet = &empty, &empty, &empty
	emptyFields.UserAgent, emptyFields.DeviceFingerprint, emptyFields.ClientID, emptyFields.Scope = &empty, &empty, &empty, &empty
	full := workerLedgerRecord(uuid.New(), expired.Add(time.Second))
	blind, ip, subnet := strings.Repeat("a", 64), "2001:db8::5", "2001:db8::/48"
	userAgent, fingerprint, client, scope := "agent|\"\\\n\u2603\u0633", "device:1", "client-one", "openid profile\nemail"
	full.IdentityBlindIndex, full.ClientIP, full.IPSubnet = &blind, &ip, &subnet
	full.UserAgent, full.DeviceFingerprint, full.ClientID, full.Scope = &userAgent, &fingerprint, &client, &scope
	rows := f.seed(t, nilFields, emptyFields, full)
	for _, row := range rows {
		var body []byte
		if err := f.admin.QueryRow(f.ctx, "SELECT public.security_ledger_canonical_body(l) FROM public.security_event_ledger l WHERE seq=$1", row.Seq).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, audit.SerializeLedger(row.record)) {
			t.Fatalf("Go/SQL canonical bytes differ for sequence %d", row.Seq)
		}
	}
	b := f.boundary(t)
	late := f.seed(t, workerLedgerRecord(uuid.New(), expired.Add(-365*24*time.Hour)))[0]
	candidates, err := f.store.Candidates(f.ctx, b, Candidate{}, 100)
	if err != nil || len(candidates) != 3 {
		t.Fatalf("captured highwater changed after append: %+v / %v", candidates, err)
	}
	// Delete separately so subsequent preflights must use a checkpoint, not a
	// surviving payload row or the arithmetic predecessor sequence.
	for _, row := range rows {
		result, err := f.store.Purge(f.ctx, b, []Candidate{row.Candidate}, false)
		if err != nil || result.Deleted != 1 {
			t.Fatalf("canonical/checkpoint preflight seq=%d: %+v / %v", row.Seq, result, err)
		}
	}
	f.assertState(t, 1, 1, 3)
	if f.count(t, "SELECT count(*) FROM public.security_event_ledger WHERE seq=$1", late.Seq) != 1 {
		t.Fatal("late expired append crossed captured highwater")
	}
	stats := f.run(t, 1, 1, false)
	if stats.Deleted != 1 {
		t.Fatalf("later run failed to discover delayed append: %+v", stats)
	}
	f.assertState(t, 0, 1, 4)
	if f.boundary(t).ThroughSeq != late.Seq || f.count(t, "SELECT erased_count FROM public.security_ledger_checkpoints") != 4 {
		t.Fatal("all-erased history lost its logical tip or compact count")
	}
}

func TestWorkerGoPreflightRejectsHistoricalCorruptionIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	rec := workerLedgerRecord(uuid.New(), time.Now().Add(-time.Hour))
	// Model a historically incorrect serializer (NULL collapsed to empty) by
	// inserting the original bad digest. Never disable or bypass ledger guards.
	wrong := rec
	empty := ""
	wrong.UserAgent = &empty
	hash := audit.ChainHash(audit.GenesisChainHash, audit.SerializeLedger(wrong))
	workerExec(t, f.ctx, f.admin, `INSERT INTO public.security_event_ledger(seq,id,account_ref,event_type,timestamp,retain_until,chain_hash)
 OVERRIDING SYSTEM VALUE
 VALUES(3,$1,$2,$3,$4,$5,$6)`, rec.ID, rec.AccountRef, rec.EventType, rec.Timestamp, rec.RetainUntil, hash)
	workerExec(t, f.ctx, f.admin, "UPDATE public.security_ledger_head SET seq=3,chain_hash=$1", hash)
	b := f.boundary(t)
	// Revoked routine execution makes ErrIntegrity evidence that Go preflight
	// rejected the body before invoking the privileged SQL routine.
	workerExec(t, f.ctx, f.admin, "REVOKE EXECUTE ON FUNCTION "+integrationPurgeRoutine+" FROM identity_ledger_purge")
	_, err := f.store.Purge(f.ctx, b, []Candidate{{Seq: 3, AccountRef: uuid.MustParse(rec.AccountRef), RetainUntil: rec.RetainUntil}}, false)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Go canonical preflight did not reject corruption first: %v", err)
	}
	f.assertState(t, 1, 0, 0)
}

func TestWorkerCheckpointAndReceiptFailureRollbackIntegration(t *testing.T) {
	for _, target := range []string{"checkpoint", "outbox"} {
		t.Run(target, func(t *testing.T) {
			f := newWorkerFixture(t)
			expired := time.Now().Add(-time.Hour)
			rows := f.seed(t, workerLedgerRecord(uuid.New(), expired), workerLedgerRecord(uuid.New(), expired))
			b := f.boundary(t)
			if result, err := f.store.Purge(f.ctx, b, []Candidate{rows[0].Candidate}, false); err != nil || result.Deleted != 1 {
				t.Fatalf("initial prefix purge: %+v / %v", result, err)
			}
			var before string
			if err := f.admin.QueryRow(f.ctx, "SELECT row_to_json(c)::text FROM public.security_ledger_checkpoints c").Scan(&before); err != nil {
				t.Fatal(err)
			}
			if target == "checkpoint" {
				workerExec(t, f.ctx, f.admin, "ALTER TABLE public.security_ledger_checkpoints ADD CONSTRAINT fixture_reject_compaction CHECK(erased_count<2)")
			} else {
				workerExec(t, f.ctx, f.admin, "ALTER TABLE public.event_outbox ADD CONSTRAINT fixture_reject_receipt CHECK(NOT admin_action) NOT VALID")
			}
			if _, err := f.store.Purge(f.ctx, b, []Candidate{rows[1].Candidate}, false); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("injected %s failure not reported: %v", target, err)
			}
			f.assertState(t, 1, 1, 1)
			var after string
			if err := f.admin.QueryRow(f.ctx, "SELECT row_to_json(c)::text FROM public.security_ledger_checkpoints c").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after || f.boundary(t).ThroughSeq != b.ThroughSeq {
				t.Fatal("failed deletion did not restore prior checkpoint/head")
			}
		})
	}
}

func TestWorkerHoldWaitFreshSnapshotIntegration(t *testing.T) {
	for _, release := range []bool{false, true} {
		name := "apply_wins"
		if release {
			name = "last_release_wins"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkerFixture(t)
			account := uuid.New() // Deliberately no users row.
			row := f.seed(t, workerLedgerRecord(account, time.Now().Add(-time.Hour)))[0]
			b := f.boundary(t)
			var holdID uuid.UUID
			if release {
				holdID = f.hold(t, f.admin, account)
			}
			holder, err := f.admin.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = holder.Rollback(context.Background()) }()
			if err := pglock.LockAccount(f.ctx, holder, account); err != nil {
				t.Fatal(err)
			}
			if release {
				workerExec(t, f.ctx, holder, "UPDATE public.legal_holds SET is_active=false WHERE id=$1", holdID)
			} else {
				f.hold(t, holder, account)
			}
			done := f.purgeAsync(b, []Candidate{row.Candidate})
			f.waitBlocked(t, holder.Conn().PgConn().PID(), f.appName)
			if err := holder.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			result := awaitWorkerPurge(t, done)
			if result.err != nil {
				t.Fatal(result.err)
			}
			if release {
				if result.batch.Deleted != 1 || result.batch.Held != 0 {
					t.Fatalf("post-lock release snapshot stale: %+v", result.batch)
				}
				f.assertState(t, 0, 1, 1)
			} else {
				if result.batch.Deleted != 0 || result.batch.Held != 1 {
					t.Fatalf("post-lock apply snapshot stale: %+v", result.batch)
				}
				f.assertState(t, 1, 0, 1)
				if f.count(t, "SELECT count(*) FROM public.event_outbox WHERE payload::jsonb->>'event_type'='legal.ledger.purge_skipped'") != 1 {
					t.Fatal("hold race omitted durable skip receipt")
				}
			}
		})
	}
}

func TestWorkerPurgeWinsBeforePreservationIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	row := f.seed(t, workerLedgerRecord(account, time.Now().Add(-time.Hour)))[0]
	b := f.boundary(t)
	rowBlocker, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rowBlocker.Rollback(context.Background()) }()
	workerExec(t, f.ctx, rowBlocker, "SELECT 1 FROM public.security_event_ledger WHERE seq=$1 FOR UPDATE", row.Seq)
	done := f.purgeAsync(b, []Candidate{row.Candidate})
	workerPID := f.waitBlocked(t, rowBlocker.Conn().PgConn().PID(), f.appName)
	holder, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	workerExec(t, f.ctx, holder, "SET LOCAL application_name='retention-preservation-waiter'")
	held := make(chan error, 1)
	go func() { held <- pglock.LockAccount(f.ctx, holder, account) }()
	f.waitBlocked(t, workerPID, "retention-preservation-waiter")
	if err := rowBlocker.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	result := awaitWorkerPurge(t, done)
	if result.err != nil || result.batch.Deleted != 1 {
		t.Fatalf("purge-first outcome: %+v / %v", result.batch, result.err)
	}
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := holder.QueryRow(f.ctx, "SELECT count(*) FROM public.security_event_ledger WHERE account_ref=$1", account).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 0 {
		t.Fatal("post-purge preservation observed a stale retained row")
	}
	f.hold(t, holder, account)
	if err := holder.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.assertState(t, 0, 1, 1)
}

func TestWorkerOverlapAndDeferredFairnessIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	expired := time.Now().Add(-time.Hour)
	rows := f.seed(t, workerLedgerRecord(uuid.New(), expired), workerLedgerRecord(uuid.New(), expired.Add(time.Second)))
	locker, err := pglock.NewPgAdvisoryLocker(f.admin, pglock.SecurityLedgerPurgeKey)
	if err != nil {
		t.Fatal(err)
	}
	acquired, release, err := locker.TryLock(f.ctx)
	if err != nil || !acquired {
		t.Fatalf("fixture overlap lock: %v", err)
	}
	defer release()
	stats := f.run(t, 1, 2, false)
	if !stats.Overlap || stats.Considered != 0 || stats.Deleted != 0 {
		t.Fatalf("overlap was not a successful no-op: %+v", stats)
	}
	f.assertState(t, 2, 0, 0)
	release()
	holder, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if err := pglock.LockAccount(f.ctx, holder, rows[0].AccountRef); err != nil {
		t.Fatal(err)
	}
	// Keep the first account locked past the worker's actual lock_timeout. The
	// second account must still be reached, not retried behind the same cursor.
	type runResult struct {
		stats Stats
		err   error
	}
	workerLocker, err := pglock.NewPgAdvisoryLocker(f.worker, pglock.SecurityLedgerPurgeKey)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{BatchSize: 1, MaxRows: 2, Timeout: 10 * time.Second}, f.store, workerLocker, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan runResult, 1)
	go func() { stats, err := svc.RunOnce(f.ctx); done <- runResult{stats, err} }()
	f.waitBlocked(t, holder.Conn().PgConn().PID(), f.appName)
	result := <-done
	if result.err != nil || result.stats.Considered != 2 || result.stats.Deferred != 1 || result.stats.Deleted != 1 {
		t.Fatalf("deferred cursor fairness: %+v / %v", result.stats, result.err)
	}
	f.assertState(t, 1, 1, 1)
	if err := holder.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	stats = f.run(t, 1, 2, false)
	if stats.Deleted != 1 || stats.Deferred != 0 {
		t.Fatalf("subsequent run did not rediscover deferred row: %+v", stats)
	}
	f.assertState(t, 0, 1, 2)
}

func TestWorkerRunLockConnectionLossDoesNotDuplicateErasureIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	expires := time.Now().Add(-time.Hour)
	rows := f.seed(t, workerLedgerRecord(uuid.New(), expires), workerLedgerRecord(uuid.New(), expires))
	b := f.boundary(t)
	candidates := []Candidate{rows[0].Candidate, rows[1].Candidate}
	connection, err := f.worker.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	workerExec(t, f.ctx, connection, "SELECT pg_advisory_lock($1)", pglock.SecurityLedgerPurgeKey)
	var terminated bool
	err = f.admin.QueryRow(f.ctx, "SELECT pg_terminate_backend($1)", connection.Conn().PgConn().PID()).Scan(&terminated)
	_ = connection.Conn().Close(f.ctx)
	connection.Release()
	if err != nil || !terminated {
		t.Fatalf("terminate run-lock connection: %v / %v", terminated, err)
	}
	// A second scheduler can now enter, while the first process still has its
	// candidate list. Transaction coordination must protect both stale batches.
	second, err := f.worker.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	workerExec(t, f.ctx, second, "SET lock_timeout='2s'")
	workerExec(t, f.ctx, second, "SELECT pg_advisory_lock($1)", pglock.SecurityLedgerPurgeKey)
	defer func() {
		_, _ = second.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", pglock.SecurityLedgerPurgeKey)
	}()
	firstDone, secondDone := f.purgeAsync(b, candidates), f.purgeAsync(b, candidates)
	first, next := awaitWorkerPurge(t, firstDone), awaitWorkerPurge(t, secondDone)
	if first.err != nil || next.err != nil || first.batch.Deleted+next.batch.Deleted != 2 {
		t.Fatalf("overlapping stale batches: %+v / %+v", first, next)
	}
	f.assertState(t, 0, 1, 1)
	if f.count(t, "SELECT erased_count FROM public.security_ledger_checkpoints") != 2 {
		t.Fatal("run lock loss duplicated the erasure certificate")
	}
}

type unavailableRetentionPublisher struct{}

func (unavailableRetentionPublisher) Publish(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	return nil, errors.New("simulated unavailable broker with private transport detail")
}

func TestWorkerDurableReceiptPublisherRecoveryIntegration(t *testing.T) {
	f := newWorkerFixture(t)
	rec := workerLedgerRecord(uuid.New(), time.Now().Add(-time.Hour))
	blind := strings.Repeat("b", 64)
	rec.IdentityBlindIndex = &blind
	f.seed(t, rec)
	stats := f.run(t, 1, 1, false)
	if stats.Deleted != 1 {
		t.Fatalf("committed purge: %+v", stats)
	}
	var payload string
	var receiptID uuid.UUID
	if err := f.admin.QueryRow(f.ctx, "SELECT id,payload FROM public.event_outbox WHERE admin_action AND subject=$1", f.subject).Scan(&receiptID, &payload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{rec.ID, rec.AccountRef, blind, "private case", "security", "checkpoint"} {
		// The system actor's name legitimately contains "security"; check only
		// envelope field presence below rather than banning that actor substring.
		if forbidden == "security" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("Class C receipt exposed erased source metadata: %s", forbidden)
		}
	}
	var env audit.Envelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatal(err)
	}
	if env.Security != nil || env.EventID != receiptID || env.EventType != "legal.ledger.purged" || env.ActorSPIFFEID != audit.LedgerRetentionActorSPIFFEID {
		t.Fatalf("invalid Class C maintenance envelope: %+v", env)
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(env.Payload), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 7 || metadata["deleted_count"] != float64(1) || metadata["considered_count"] != float64(1) || metadata["held_count"] != float64(0) || metadata["dry_run"] != false || metadata["operation_id"] != receiptID.String() {
		t.Fatalf("nonminimal or incorrect maintenance receipt: %+v", metadata)
	}
	failed, err := adminaction.NewPublisher(f.admin, unavailableRetentionPublisher{}, f.subject, adminaction.PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := failed.RunOnce(f.ctx); n != 0 || !errors.Is(err, adminaction.ErrPublish) {
		t.Fatalf("publisher outage not retryable: %d / %v", n, err)
	}
	if f.count(t, "SELECT count(*) FROM public.event_outbox WHERE id=$1 AND published_at IS NULL AND attempts=1 AND last_error='publish_unacknowledged'", receiptID) != 1 {
		t.Fatal("broker outage lost or prematurely acknowledged committed intent")
	}
	f.assertState(t, 0, 1, 1)
	streamName := "RETENTION_WORKER_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	stream, err := f.js.CreateStream(f.ctx, jetstream.StreamConfig{Name: streamName, Subjects: []string{f.subject}, Storage: jetstream.MemoryStorage})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.js.DeleteStream(context.Background(), streamName) })
	// Advance only the retry schedule, not elapsed wall time, to make recovery deterministic.
	workerExec(t, f.ctx, f.admin, "UPDATE public.event_outbox SET next_attempt_at=now()-interval '1 second' WHERE id=$1", receiptID)
	recovered, err := adminaction.NewPublisher(f.admin, f.js, f.subject, adminaction.PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := recovered.RunOnce(f.ctx); n != 1 || err != nil {
		t.Fatalf("publisher recovery: %d / %v", n, err)
	}
	if n, err := recovered.RunOnce(f.ctx); n != 0 || err != nil {
		t.Fatalf("published intent replayed: %d / %v", n, err)
	}
	info, err := stream.Info(f.ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("JetStream acknowledged message count: %+v / %v", info, err)
	}
	msg, err := stream.GetMsg(f.ctx, 1)
	if err != nil || !bytes.Equal(msg.Data, []byte(payload)) {
		t.Fatalf("published receipt changed: %v", err)
	}
	if f.count(t, "SELECT count(*) FROM public.event_outbox WHERE id=$1 AND published_at IS NOT NULL", receiptID) != 1 {
		t.Fatal("acknowledged delivery not persisted")
	}
}
