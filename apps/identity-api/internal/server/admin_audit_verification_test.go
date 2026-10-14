package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

// These tests cover the HTTP contract of the two verification routes: the status
// code mapping, the recorded Class C event, and the response projection. The
// chain walking itself is covered in internal/audit/ledgerproof; both routes now
// share that one walker, so there is no second recomputation loop here to test.

// verifySource is an in-memory chain for one of the two chains.
type verifySource struct {
	chain ledgerproof.Chain
	head  ledgerproof.Head
	nodes []ledgerproof.Node
}

func (s *verifySource) Head(context.Context) (ledgerproof.Head, error) { return s.head, nil }

func (s *verifySource) HashAt(_ context.Context, seq int64) ([]byte, error) {
	for _, n := range s.nodes {
		if n.Seq == seq {
			return n.ChainHash, nil
		}
	}
	return nil, ledgerproof.ErrUnknownSeq
}

func (s *verifySource) Page(_ context.Context, after, through int64, limit int32) ([]ledgerproof.Node, error) {
	var out []ledgerproof.Node
	for _, n := range s.nodes {
		if n.Seq > after && n.Seq <= through && int32(len(out)) < limit {
			out = append(out, n)
		}
	}
	return out, nil
}

// buildAuditSource creates a well-formed audit chain at the given positions.
// Non-contiguous sequences are deliberate: allocation holes are legal and must
// not break hash linkage.
func buildAuditSource(t *testing.T, sequences ...int64) *verifySource {
	t.Helper()
	src := &verifySource{chain: ledgerproof.ChainAudit}
	prev := audit.AuditGenesis()
	for _, seq := range sequences {
		rec := audit.AuditRecord{
			ID: uuid.NewString(), ActorID: uuid.NewString(),
			Payload:   fmt.Sprintf(`{"private":"private-value-%d"}`, seq),
			ClientIP:  "192.0.2.254",
			UserAgent: "private-agent",
			Timestamp: time.Unix(seq, 0).UTC(),
		}
		leafHash, err := audit.LeafAudit(rec)
		if err != nil {
			t.Fatal(err)
		}
		prev = audit.ChainAudit(prev, leafHash)
		src.nodes = append(src.nodes, ledgerproof.Node{
			Seq: seq, LeafHash: leafHash.Bytes(), ChainHash: prev.Bytes(),
			Recompute: func() (audit.Digest, error) { return audit.LeafAudit(rec) },
		})
	}
	if n := len(sequences); n > 0 {
		src.head = ledgerproof.Head{Seq: sequences[n-1], MaxSeq: sequences[n-1], Hash: prev.Bytes()}
	} else {
		src.head = ledgerproof.Head{Hash: audit.AuditGenesis().Bytes()}
	}
	return src
}

func verifyRequest(t *testing.T, chain ledgerproof.Chain, src *verifySource, query string) (*httptest.ResponseRecorder, adminLedgerVerifyResponse, *adminaction.Operation) {
	t.Helper()
	s := &Server{
		cfg:    config.Config{Admin: config.AdminConfig{ChainVerifyMaxLimit: 5000}},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	op := &adminaction.Operation{ID: uuid.New()}
	route := "/api/v1/admin/audit-logs/verify"
	if chain == ledgerproof.ChainLedger {
		route = "/api/v1/admin/ledger/verify"
	}
	r := httptest.NewRequest(http.MethodGet, route+query, nil)
	r = r.WithContext(adminaction.WithContext(rbac.WithActor(r.Context(), uuid.New()), op))
	w := httptest.NewRecorder()

	verify := func(ctx context.Context, p ledgerproof.Params) (ledgerproof.Result, error) {
		return ledgerproof.Verify(ctx, src, p)
	}
	s.runChainVerification(w, r, chain, verify)

	var response adminLedgerVerifyResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode response: %v (%s)", err, w.Body.String())
		}
	}
	return w, response, op
}

func TestAdminVerifyAuditChainClean(t *testing.T) {
	src := buildAuditSource(t, 2, 8, 11, 18) // allocation holes
	w, resp, op := verifyRequest(t, ledgerproof.ChainAudit, src, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if !resp.Verified || !resp.Complete || resp.Checked != 4 {
		t.Fatalf("verified=%v complete=%v checked=%d reason=%v", resp.Verified, resp.Complete, resp.Checked, resp.FailureReason)
	}
	if resp.Chain != "audit" || resp.SeedSource != "genesis" {
		t.Errorf("chain=%q seed_source=%q", resp.Chain, resp.SeedSource)
	}
	if resp.ThroughSeq != 18 || resp.LastSeq == nil || *resp.LastSeq != 18 {
		t.Errorf("through_seq=%d last_seq=%v", resp.ThroughSeq, resp.LastSeq)
	}

	// Reading the tamper-evident log is itself auditable, and the recorded event
	// must describe the window rather than the records.
	if op.Event.EventType != audit.EventAdminChainVerified || op.Event.ActionStatus != audit.StatusSuccess {
		t.Errorf("event = %q/%q", op.Event.EventType, op.Event.ActionStatus)
	}
	if op.Event.Security != nil {
		t.Error("a verification read must not be recorded as a Class B security event")
	}
	encoded, err := json.Marshal(op.Event.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"private-value", "private-agent", "192.0.2.254"} {
		if bytesContains(encoded, leaked) {
			t.Errorf("verification audit payload leaked record content %q", leaked)
		}
	}
}

func TestAdminVerifyPaginatesWithCursor(t *testing.T) {
	src := buildAuditSource(t, 2, 8, 11, 18)

	w, first, _ := verifyRequest(t, ledgerproof.ChainAudit, src, "?limit=2")
	if w.Code != http.StatusOK || !first.Verified || first.Complete || first.Checked != 2 {
		t.Fatalf("first page: %s", w.Body.String())
	}
	if first.NextAfterSeq == nil || *first.NextAfterSeq != 8 {
		t.Fatalf("next_after_seq = %v, want 8", first.NextAfterSeq)
	}
	if first.LastHash == "" {
		t.Fatal("a partial page must report the continuation digest")
	}

	w, second, _ := verifyRequest(t, ledgerproof.ChainAudit, src,
		"?limit=2&after_seq=8&through_seq=18&predecessor_hash="+first.LastHash)
	if w.Code != http.StatusOK || !second.Verified || !second.Complete || second.Checked != 2 {
		t.Fatalf("second page: %s", w.Body.String())
	}
	if second.SeedSource != "supplied_predecessor" {
		t.Errorf("seed_source = %q, want supplied_predecessor", second.SeedSource)
	}
}

// TestAdminVerifyReportsTampering is the failure contract: a 200 carrying
// verified=false, the offending seq, and a failed audit status. A rewritten
// record must not surface as a 500, because an operator needs the seq.
func TestAdminVerifyReportsTampering(t *testing.T) {
	src := buildAuditSource(t, 1, 2, 3)
	rewritten := audit.AuditRecord{ID: uuid.NewString(), EventType: "rewritten", Timestamp: time.Unix(2, 0).UTC()}
	src.nodes[1].Recompute = func() (audit.Digest, error) { return audit.LeafAudit(rewritten) }

	w, resp, op := verifyRequest(t, ledgerproof.ChainAudit, src, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 so the break is reportable", w.Code)
	}
	if resp.Verified {
		t.Fatal("a rewritten record verified clean")
	}
	if resp.FailureReason == nil || *resp.FailureReason != "leaf_mismatch" {
		t.Errorf("failure_reason = %v, want leaf_mismatch", resp.FailureReason)
	}
	if resp.BrokenAtSeq == nil || *resp.BrokenAtSeq != 2 {
		t.Errorf("broken_at_seq = %v, want 2", resp.BrokenAtSeq)
	}
	if op.Event.ActionStatus != audit.StatusFailure {
		t.Errorf("audit status = %q, want failure so alerting fires", op.Event.ActionStatus)
	}
}

// TestAdminVerifyLedgerAcceptsLawfulErasure covers the v2 behaviour the HTTP
// layer has to surface: an erased payload is verifiable and counted, not an
// error. v1 reported purged spans and a restart flag here because a removed
// record broke the chain; neither concept exists now.
func TestAdminVerifyLedgerAcceptsLawfulErasure(t *testing.T) {
	src := &verifySource{chain: ledgerproof.ChainLedger}
	prev := audit.LedgerGenesis()
	op := "33333333-3333-4333-8333-333333333333"
	for seq := int64(1); seq <= 3; seq++ {
		blind := "abc"
		rec := audit.LedgerRecord{
			ID: uuid.NewString(), AccountRef: uuid.NewString(),
			IdentityBlindIndex: &blind, BlindIndexVersion: 1, EventType: "auth.login",
			Timestamp: time.Unix(seq, 0).UTC(), RetainUntil: time.Unix(seq+1000, 0).UTC(),
		}
		leafHash, err := audit.LeafLedger(rec)
		if err != nil {
			t.Fatal(err)
		}
		prev = audit.ChainLedger(prev, leafHash)
		node := ledgerproof.Node{Seq: seq, LeafHash: leafHash.Bytes(), ChainHash: prev.Bytes()}
		if seq == 2 {
			// Payload erased; leaf retained; erasure record present.
			node.ErasureOperation = &op
		} else {
			node.Recompute = func() (audit.Digest, error) { return audit.LeafLedger(rec) }
		}
		src.nodes = append(src.nodes, node)
	}
	src.head = ledgerproof.Head{Seq: 3, MaxSeq: 3, Hash: prev.Bytes()}

	w, resp, operation := verifyRequest(t, ledgerproof.ChainLedger, src, "")
	if w.Code != http.StatusOK || !resp.Verified || !resp.Complete {
		t.Fatalf("an erased span broke ledger verification: %s", w.Body.String())
	}
	if resp.ErasedChecked != 1 {
		t.Errorf("erased_checked = %d, want 1", resp.ErasedChecked)
	}
	if resp.Checked != 3 {
		t.Errorf("checked = %d, want 3", resp.Checked)
	}
	if operation.Event.ActionStatus != audit.StatusSuccess {
		t.Errorf("a lawful erasure must not be audited as a verification failure, got %q", operation.Event.ActionStatus)
	}
}

// TestAdminVerifyLedgerRejectsUnexplainedGap is the check v1 could not make.
func TestAdminVerifyLedgerRejectsUnexplainedGap(t *testing.T) {
	src := &verifySource{chain: ledgerproof.ChainLedger}
	prev := audit.LedgerGenesis()
	for seq := int64(1); seq <= 2; seq++ {
		rec := audit.LedgerRecord{
			ID: uuid.NewString(), AccountRef: uuid.NewString(), BlindIndexVersion: 0,
			EventType: "auth.login", Timestamp: time.Unix(seq, 0).UTC(), RetainUntil: time.Unix(seq+10, 0).UTC(),
		}
		leafHash, err := audit.LeafLedger(rec)
		if err != nil {
			t.Fatal(err)
		}
		prev = audit.ChainLedger(prev, leafHash)
		node := ledgerproof.Node{Seq: seq, LeafHash: leafHash.Bytes(), ChainHash: prev.Bytes()}
		if seq == 1 {
			node.Recompute = func() (audit.Digest, error) { return audit.LeafLedger(rec) }
		}
		// seq 2: payload gone, no erasure record.
		src.nodes = append(src.nodes, node)
	}
	src.head = ledgerproof.Head{Seq: 2, MaxSeq: 2, Hash: prev.Bytes()}

	w, resp, operation := verifyRequest(t, ledgerproof.ChainLedger, src, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if resp.Verified {
		t.Fatal("an unexplained missing payload verified clean")
	}
	if resp.FailureReason == nil || *resp.FailureReason != "payload_absent_without_erasure_record" {
		t.Errorf("failure_reason = %v", resp.FailureReason)
	}
	if operation.Event.ActionStatus != audit.StatusFailure {
		t.Error("an unexplained deletion must audit as a failure")
	}
}

func TestAdminVerifyRejectsUnknownSeq(t *testing.T) {
	src := buildAuditSource(t, 1, 2)
	w, _, _ := verifyRequest(t, ledgerproof.ChainAudit, src, "?after_seq=99&through_seq=100")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAdminVerifyRejectsMalformedParams(t *testing.T) {
	src := buildAuditSource(t, 1, 2)
	for _, query := range []string{
		"?limit=0&after_seq=1",            // after_seq without through_seq
		"?after_seq=5&through_seq=1",      // inverted range
		"?predecessor_hash=zz",            // not hex
		"?limit=-1",                       // negative limit
	} {
		w, _, _ := verifyRequest(t, ledgerproof.ChainAudit, src, query)
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q: status = %d, want 400", query, w.Code)
		}
	}
}

func TestAdminVerifyPropagatesVerifierFailure(t *testing.T) {
	s := &Server{
		cfg:    config.Config{Admin: config.AdminConfig{ChainVerifyMaxLimit: 5000}},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs/verify", nil)
	r = r.WithContext(adminaction.WithContext(rbac.WithActor(r.Context(), uuid.New()), &adminaction.Operation{ID: uuid.New()}))
	w := httptest.NewRecorder()
	s.runChainVerification(w, r, ledgerproof.ChainAudit,
		func(context.Context, ledgerproof.Params) (ledgerproof.Result, error) {
			return ledgerproof.Result{}, errors.New("database unavailable")
		})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestAdminVerifyMissingHeadIsBadRequest(t *testing.T) {
	src := buildAuditSource(t, 1)
	src.head.Hash = nil
	w, _, _ := verifyRequest(t, ledgerproof.ChainAudit, src, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an uninitialized head", w.Code)
	}
}

func bytesContains(haystack []byte, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexOf(string(haystack), needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
