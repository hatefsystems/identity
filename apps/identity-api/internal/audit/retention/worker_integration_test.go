//go:build integration

package retention

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// Real-role integration coverage for the v2 erasure path.
//
// What changed from v1: there is no SECURITY DEFINER routine to vet, no
// checkpoint table to compact, and no canonical-body recomputation in SQL. So the
// tests that proved those things are gone, and the ones here instead prove the
// three properties the split is supposed to deliver:
//
//   - an erasure removes only the payload, and the chain still verifies from
//     genesis afterwards;
//   - the purge role cannot touch a chain node even if it tries;
//   - an active hold still outranks every retention timer, decided under the
//     account locks rather than from the candidate listing.
//
// Every test runs as the real `identity_ledger_purge` login with a hostile
// session default (repeatable read, Pacific/Honolulu), so nothing here passes
// because of an accidentally privileged connection or a convenient timezone.

func expired(t *testing.T, f *workerFixture, account uuid.UUID, ago time.Duration) audit.LedgerRecord {
	t.Helper()
	return workerLedgerRecord(account, time.Now().UTC().Add(-ago))
}

// TestWorkerErasesPayloadAndKeepsChainVerifiable is the core acceptance test for
// the whole change: after a real purge by the real role, the chain table still
// reproduces its head from genesis.
func TestWorkerErasesPayloadAndKeepsChainVerifiable(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	seeded := f.seed(t,
		expired(t, f, account, 40*24*time.Hour),
		expired(t, f, account, 39*24*time.Hour),
		workerLedgerRecord(account, time.Now().UTC().Add(365*24*time.Hour)), // retained
	)
	headBefore := f.chainHead(t)

	stats := f.run(t, 10, 100, false)
	if stats.Deleted != 2 {
		t.Fatalf("deleted = %d, want 2: %+v", stats.Deleted, stats)
	}

	// Payloads gone, chain nodes all still present. Two erasure spans, not one:
	// the fixture seeds with sequence gaps, so the two erased rows are not
	// numerically adjacent. Collapsing them would claim a span covering a node
	// that was never erased.
	f.assertState(t, 1, 2, 1)
	if got := f.count(t, "SELECT count(*) FROM public.security_ledger_chain"); got != 3 {
		t.Fatalf("chain nodes = %d, want 3; an erasure removed tamper-evidence", got)
	}
	// The head must not move: erasure is not an append.
	if after := f.chainHead(t); after != headBefore {
		t.Fatalf("erasure moved the chain head from %s to %s", headBefore.Hex(), after.Hex())
	}
	// And the chain must still verify end to end across the erased span.
	f.assertChainVerifies(t)

	// The surviving payload is the retained one.
	var survivingSeq int64
	if err := f.admin.QueryRow(f.ctx, "SELECT seq FROM public.security_event_ledger").Scan(&survivingSeq); err != nil {
		t.Fatal(err)
	}
	if survivingSeq != seeded[2].Seq {
		t.Errorf("surviving payload seq = %d, want %d", survivingSeq, seeded[2].Seq)
	}
}

// TestWorkerRecordsErasureSpanAndReceipt covers the proof side: an absent payload
// has to be explainable, or verification reports it as tampering.
func TestWorkerRecordsErasureSpanAndReceipt(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	seeded := f.seed(t,
		expired(t, f, account, 40*24*time.Hour),
		expired(t, f, account, 39*24*time.Hour),
	)

	if stats := f.run(t, 10, 100, false); stats.Deleted != 2 {
		t.Fatalf("deleted = %d, want 2", stats.Deleted)
	}

	// The seeded sequences are deliberately non-contiguous, so these two erasures
	// must produce two spans rather than one collapsed range. Numeric adjacency is
	// not chain adjacency.
	var spans, distinctOps int
	var operation uuid.UUID
	if err := f.admin.QueryRow(f.ctx,
		`SELECT count(*), count(DISTINCT operation_id), (array_agg(operation_id))[1]
		 FROM public.security_ledger_erasures`).Scan(&spans, &distinctOps, &operation); err != nil {
		t.Fatal(err)
	}
	if spans != 2 {
		t.Errorf("erasure spans = %d, want 2 for non-adjacent sequences", spans)
	}
	// One run is one operation, however many spans it produced, so a single
	// receipt accounts for all of them.
	if distinctOps != 1 {
		t.Errorf("distinct operation ids = %d, want 1 per run", distinctOps)
	}

	// Every erased node must be covered by a span.
	var uncovered int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM public.security_ledger_chain c
WHERE NOT EXISTS (SELECT 1 FROM public.security_event_ledger l WHERE l.seq=c.seq)
  AND NOT EXISTS (SELECT 1 FROM public.security_ledger_erasures e WHERE c.seq BETWEEN e.first_seq AND e.last_seq)`).Scan(&uncovered); err != nil {
		t.Fatal(err)
	}
	if uncovered != 0 {
		t.Errorf("%d erased nodes have no erasure record; verification would report tampering", uncovered)
	}

	// The receipt is enqueued to the configured subject, carries the same
	// operation id, and is marked admin_action so the existing publisher drains it.
	var subject, payload string
	var adminAction bool
	if err := f.admin.QueryRow(f.ctx,
		"SELECT subject,payload::text,admin_action FROM public.event_outbox").Scan(&subject, &payload, &adminAction); err != nil {
		t.Fatal(err)
	}
	if subject != f.subject {
		t.Errorf("receipt subject = %q, want %q", subject, f.subject)
	}
	if !adminAction {
		t.Error("the receipt must be admin_action so admin-audit-publisher drains it")
	}
	var envelope audit.Envelope
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		t.Fatalf("receipt is not a decodable envelope: %v", err)
	}
	if envelope.EventType != audit.EventLegalLedgerPurged {
		t.Errorf("receipt event type = %q, want %q", envelope.EventType, audit.EventLegalLedgerPurged)
	}
	if !strings.Contains(payload, operation.String()) {
		t.Error("the receipt does not name the operation id recorded on the erasure span")
	}
	// The receipt must not carry the erased subject's attribution material.
	for _, leaked := range []string{seeded[0].record.AccountRef, account.String()} {
		if strings.Contains(payload, leaked) {
			t.Errorf("receipt leaked subject attribution %q", leaked)
		}
	}
}

// TestWorkerHoldOutranksRetention keeps the precedence rule that the whole
// compliance story rests on: holds > retention, unconditionally.
func TestWorkerHoldOutranksRetention(t *testing.T) {
	f := newWorkerFixture(t)
	held, free := uuid.New(), uuid.New()
	f.seed(t,
		expired(t, f, held, 400*24*time.Hour),
		expired(t, f, free, 400*24*time.Hour),
	)
	workerExec(t, f.ctx, f.admin, `INSERT INTO public.legal_holds(account_ref,reason,requesting_authority,legal_basis,applied_by)
VALUES($1,'integration','court','legal claims',$2)`, held, uuid.New())

	stats := f.run(t, 10, 100, false)
	if stats.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1 (the unheld subject only): %+v", stats.Deleted, stats)
	}

	var remaining uuid.UUID
	if err := f.admin.QueryRow(f.ctx, "SELECT account_ref FROM public.security_event_ledger").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != held {
		t.Errorf("surviving payload belongs to %s, want the held subject %s", remaining, held)
	}
	f.assertChainVerifies(t)
}

// TestWorkerHoldAppliedAfterListingStillBlocks is the race the candidate listing
// cannot settle: the listing runs before the account locks, so eligibility has to
// be re-decided under them.
func TestWorkerHoldAppliedAfterListingStillBlocks(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	f.seed(t, expired(t, f, account, 400*24*time.Hour))

	boundary := f.boundary(t)
	candidates, err := f.store.Candidates(f.ctx, boundary, Candidate{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}

	// A hold lands between the listing and the purge, exactly as a DPO action
	// would.
	workerExec(t, f.ctx, f.admin, `INSERT INTO public.legal_holds(account_ref,reason,requesting_authority,legal_basis,applied_by)
VALUES($1,'late hold','court','legal claims',$2)`, account, uuid.New())

	result, err := f.store.Purge(f.ctx, boundary, candidates, false)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if result.Deleted != 0 || result.Held != 1 {
		t.Fatalf("a hold applied after listing did not block the purge: %+v", result)
	}
	if got := f.count(t, "SELECT count(*) FROM public.security_event_ledger"); got != 1 {
		t.Errorf("payload rows = %d, want 1 retained under hold", got)
	}
	// Nothing was erased, so nothing may be recorded as erased.
	f.assertState(t, 1, 0, 0)
}

// TestWorkerDryRunChangesNothing proves the rollback is a full-fidelity dry run:
// the erasure, the span, and the receipt all disappear together.
func TestWorkerDryRunChangesNothing(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	f.seed(t, expired(t, f, account, 400*24*time.Hour))
	headBefore := f.chainHead(t)

	stats := f.run(t, 10, 100, true)
	if stats.Deleted != 0 || stats.WouldDelete != 1 {
		t.Fatalf("a dry run must report WouldDelete and erase nothing: %+v", stats)
	}
	f.assertState(t, 1, 0, 0)
	if after := f.chainHead(t); after != headBefore {
		t.Error("dry run moved the chain head")
	}
	f.assertChainVerifies(t)
}

// TestWorkerCannotTouchChainTable is the privilege boundary. Even holding DELETE
// on the payload, the purge role must be unable to remove or rewrite a node —
// that is what makes erasure safe rather than merely recorded.
func TestWorkerCannotTouchChainTable(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	seeded := f.seed(t, expired(t, f, account, 400*24*time.Hour))

	for name, query := range map[string]string{
		"delete node":    "DELETE FROM public.security_ledger_chain WHERE seq=$1",
		"update node":    "UPDATE public.security_ledger_chain SET chain_hash=leaf_hash WHERE seq=$1",
		"insert node":    "INSERT INTO public.security_ledger_chain(seq,event_id,leaf_hash,chain_hash) VALUES($1,gen_random_uuid(),sha256('a'),sha256('b'))",
		"truncate":       "TRUNCATE public.security_ledger_chain",
		"advance head":   "SELECT public.advance_chain_head('ledger',0,1,1,1)",
		"update head":    "UPDATE public.security_ledger_head SET seq=0",
		"update payload": "UPDATE public.security_event_ledger SET event_type='rewritten' WHERE seq=$1",
		"delete erasure": "DELETE FROM public.security_ledger_erasures WHERE first_seq=$1",
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if strings.Contains(query, "$1") {
				_, err = f.worker.Exec(f.ctx, query, seeded[0].Seq)
			} else {
				_, err = f.worker.Exec(f.ctx, query)
			}
			if err == nil {
				t.Fatalf("the purge role was allowed to %s", name)
			}
		})
	}
	f.assertChainVerifies(t)
}

// TestWorkerProbeRejectsOverPrivilegedRole keeps the startup gate meaningful: a
// role that can reach the chain must not be accepted as a purge worker.
func TestWorkerProbeRejectsOverPrivilegedRole(t *testing.T) {
	f := newWorkerFixture(t)

	for _, tc := range []struct {
		name          string
		grant, revoke string
	}{
		{"chain insert", "GRANT INSERT ON public.security_ledger_chain TO identity_ledger_purge",
			"REVOKE INSERT ON public.security_ledger_chain FROM identity_ledger_purge"},
		{"chain delete", "GRANT DELETE ON public.security_ledger_chain TO identity_ledger_purge",
			"REVOKE DELETE ON public.security_ledger_chain FROM identity_ledger_purge"},
		{"payload update", "GRANT UPDATE ON public.security_event_ledger TO identity_ledger_purge",
			"REVOKE UPDATE ON public.security_event_ledger FROM identity_ledger_purge"},
		{"head update", "GRANT UPDATE ON public.security_ledger_head TO identity_ledger_purge",
			"REVOKE UPDATE ON public.security_ledger_head FROM identity_ledger_purge"},
		{"erasure delete", "GRANT DELETE ON public.security_ledger_erasures TO identity_ledger_purge",
			"REVOKE DELETE ON public.security_ledger_erasures FROM identity_ledger_purge"},
		{"head advance", "GRANT EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) TO identity_ledger_purge",
			"REVOKE EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) FROM identity_ledger_purge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workerExec(t, f.ctx, f.admin, tc.grant)
			t.Cleanup(func() { workerExec(t, context.Background(), f.admin, tc.revoke) })
			if err := f.store.Probe(f.ctx); !errors.Is(err, ErrPrivilege) {
				t.Fatalf("probe accepted a role holding %s: %v", tc.name, err)
			}
		})
	}

	// Sanity: the correctly provisioned role still passes once the extra grant is
	// revoked, so these tests are detecting the grant rather than a broken probe.
	if err := f.store.Probe(f.ctx); err != nil {
		t.Fatalf("correctly provisioned role rejected: %v", err)
	}
}

// TestWorkerProbeRequiresArmedGuards covers the other half of the gate: erasure
// is only bounded while the immutability triggers are enabled.
func TestWorkerProbeRequiresArmedGuards(t *testing.T) {
	f := newWorkerFixture(t)
	for _, tc := range []struct{ table, trigger string }{
		{"security_event_ledger", "trg_security_event_ledger_immutable"},
		{"security_event_ledger", "trg_security_event_ledger_no_truncate"},
		{"security_ledger_chain", "trg_security_ledger_chain_append_only"},
		{"security_ledger_chain", "trg_security_ledger_chain_no_truncate"},
	} {
		t.Run(tc.trigger, func(t *testing.T) {
			disable := "ALTER TABLE public." + tc.table + " DISABLE TRIGGER " + tc.trigger
			enable := "ALTER TABLE public." + tc.table + " ENABLE TRIGGER " + tc.trigger
			workerExec(t, f.ctx, f.admin, disable)
			restored := false
			t.Cleanup(func() {
				if !restored {
					workerExec(t, context.Background(), f.admin, enable)
				}
			})
			if err := f.store.Probe(f.ctx); !errors.Is(err, ErrPrivilege) {
				t.Fatalf("probe accepted a disarmed %s: %v", tc.trigger, err)
			}
			workerExec(t, f.ctx, f.admin, enable)
			restored = true
		})
	}
}

// TestWorkerRetentionSubjectMustBeProvisioned keeps an unprovisioned receipt
// subject fatal rather than defaulting to something publishable.
func TestWorkerRetentionSubjectMustBeProvisioned(t *testing.T) {
	f := newWorkerFixture(t)
	store, err := NewPgStore(f.worker, "identity.audit.not-provisioned")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Probe(f.ctx); !errors.Is(err, ErrPrivilege) {
		t.Fatalf("probe accepted an unprovisioned receipt subject: %v", err)
	}
}

// TestWorkerBoundaryRejectsInconsistentHead keeps the worker from erasing against
// a head it cannot reconcile with the chain table.
func TestWorkerBoundaryRejectsInconsistentHead(t *testing.T) {
	f := newWorkerFixture(t)
	f.seed(t, expired(t, f, uuid.New(), 400*24*time.Hour))

	// Rewind the head behind the chain. Erasing under this state would let a purge
	// decide eligibility against history the head does not cover.
	workerExec(t, f.ctx, f.admin, "UPDATE public.security_ledger_head SET seq=0, chain_hash=$1", audit.LedgerGenesis().Bytes())
	if _, err := f.store.Capture(f.ctx); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("capture accepted a head inconsistent with the chain: %v", err)
	}
}
