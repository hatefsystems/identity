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
	"strconv"
	"strings"
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
		if n.Seq > after && n.Seq <= through && len(out) < int(limit) {
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
	prev := audit.Genesis()
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
		src.head = ledgerproof.Head{Hash: audit.Genesis().Bytes()}
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
		if response.CanonicalVersion != 2 {
			t.Fatalf("verifier omitted or changed its canonical format version: %d", response.CanonicalVersion)
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

func TestAdminVerifyFailureCoordinates(t *testing.T) {
	for _, tc := range []struct {
		reason                    string
		mutate                    func(*verifySource)
		checked                   int
		first, last, broken, next string
		auditStatus               string
	}{
		{"invalid_leaf_hash", func(src *verifySource) { src.nodes[0].LeafHash = []byte{1} }, 0, "null", "null", `"2"`, "null", audit.StatusFailure},
		{"invalid_chain_hash", func(src *verifySource) { src.nodes[0].ChainHash = []byte{1} }, 0, "null", "null", `"2"`, "null", audit.StatusFailure},
		{"record_not_serializable", func(src *verifySource) {
			src.nodes[0].Recompute = func() (audit.Digest, error) { return audit.Digest{}, errors.New("private-serialization-detail") }
		}, 1, `"2"`, `"2"`, `"2"`, "null", audit.StatusFailure},
		{"no_stored_records", func(src *verifySource) { src.nodes = nil }, 0, "null", "null", "null", "null", audit.StatusSuccess},
		{"head_mismatch", func(src *verifySource) { src.head.Hash = audit.Genesis().Bytes() }, 2, `"2"`, `"8"`, `"8"`, `"8"`, audit.StatusFailure},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			src := buildAuditSource(t, 2, 8)
			tc.mutate(src)
			w, resp, op := verifyRequest(t, ledgerproof.ChainAudit, src, "")
			if w.Code != http.StatusOK || resp.Verified || resp.Complete || resp.FailureReason == nil || *resp.FailureReason != tc.reason {
				t.Fatalf("integrity failure was not reportable as HTTP 200: %s", w.Body.String())
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			for field, want := range map[string]string{
				"after_seq": `"0"`, "through_seq": `"8"`, "checked": strconv.Itoa(tc.checked),
				"first_seq": tc.first, "last_seq": tc.last, "broken_at_seq": tc.broken, "next_after_seq": tc.next,
			} {
				if string(fields[field]) != want {
					t.Errorf("%s = %s, want %s", field, fields[field], want)
				}
			}
			if resp.SeedSource != "genesis" || resp.SeedHash != audit.Genesis().Hex() || resp.Scope != auditVerifyScope {
				t.Fatal("failure changed the reported seed or verification scope")
			}
			if tc.reason == "head_mismatch" {
				last, err := audit.DecodeDigest(src.nodes[1].ChainHash)
				if err != nil {
					t.Fatal(err)
				}
				if resp.LastHash != last.Hex() || resp.ExpectedHash == nil || *resp.ExpectedHash != last.Hex() || resp.StoredHash == nil || *resp.StoredHash != audit.Genesis().Hex() {
					t.Fatal("head mismatch lost its terminal digest or compared hashes")
				}
			} else if resp.LastHash != resp.SeedHash || string(fields["expected_hash"]) != "null" || string(fields["stored_hash"]) != "null" {
				t.Fatal("uncheckable records manufactured digest evidence")
			}
			if op.Event.EventType != audit.EventAdminChainVerified || op.Event.ActionStatus != tc.auditStatus || op.Event.Payload["failure_reason"] != tc.reason || op.Event.Payload["checked"] != tc.checked || op.Event.Payload["after_seq"] != int64(0) || op.Event.Payload["through_seq"] != int64(8) {
				t.Fatal("verification failure audit status or numeric metadata changed")
			}
			encoded, err := json.Marshal(op.Event.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(w.Body.String(), "private-serialization-detail") || strings.Contains(string(encoded), "private-serialization-detail") {
				t.Fatal("serialization error details escaped the content-free proof contract")
			}
		})
	}
}

func TestAdminVerifyEmptyChainsHaveNullableCoordinates(t *testing.T) {
	for _, chain := range []ledgerproof.Chain{ledgerproof.ChainAudit, ledgerproof.ChainLedger} {
		t.Run(string(chain), func(t *testing.T) {
			src := &verifySource{chain: chain, head: ledgerproof.Head{Hash: chain.Genesis().Bytes()}}
			w, resp, op := verifyRequest(t, chain, src, "")
			if w.Code != http.StatusOK || !resp.Verified || !resp.Complete || resp.Checked != 0 || resp.ErasedChecked != 0 || resp.FailureReason != nil || resp.SeedHash != chain.Genesis().Hex() || resp.LastHash != resp.SeedHash {
				t.Fatalf("empty chain contract changed: %s", w.Body.String())
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			for field, want := range map[string]string{
				"after_seq": `"0"`, "through_seq": `"0"`, "checked": "0",
				"first_seq": "null", "last_seq": "null", "broken_at_seq": "null", "next_after_seq": "null",
				"expected_hash": "null", "stored_hash": "null",
			} {
				if string(fields[field]) != want {
					t.Errorf("%s = %s, want %s", field, fields[field], want)
				}
			}
			if chain == ledgerproof.ChainLedger && string(fields["erased_checked"]) != "0" {
				t.Fatal("empty ledger omitted its numeric erasure count")
			}
			if op.Event.ActionStatus != audit.StatusSuccess {
				t.Fatal("empty initialized chain was audited as an integrity failure")
			}
		})
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
		"?limit=0&after_seq=1",       // after_seq without through_seq
		"?after_seq=5&through_seq=1", // inverted range
		"?predecessor_hash=zz",       // not hex
		"?limit=-1",                  // negative limit
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
