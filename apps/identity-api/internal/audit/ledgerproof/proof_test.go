package ledgerproof

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// These tests cover the three checks v2 verification makes, and in particular the
// one v1 could not make at all: deciding whether an absent payload was lawfully
// erased or silently deleted. Under v1 an erased record left a hole that had to be
// bridged with stored checkpoint digests, so "payload missing" was indistinguishable
// from "payload removed" and could only ever be tolerated.

var proofTime = time.Date(2026, 5, 6, 7, 8, 9, 101112000, time.UTC)

// fakeSource is an in-memory chain. It is deliberately not a mock of the SQL
// layer: the properties under test are about the walker's decisions, and a fake
// lets a test build a chain that the database's own constraints would refuse to
// store (a non-linking node, a rewritten payload, an unexplained gap).
type fakeSource struct {
	chain     Chain
	head      Head
	nodes     []Node
	headErr   error
	pageErr   error
	hashErr   error
	pageCalls int
}

func (f *fakeSource) Head(context.Context) (Head, error) {
	if f.headErr != nil {
		return Head{}, f.headErr
	}
	return f.head, nil
}

func (f *fakeSource) HashAt(_ context.Context, seq int64) ([]byte, error) {
	if f.hashErr != nil {
		return nil, f.hashErr
	}
	for _, n := range f.nodes {
		if n.Seq == seq {
			return n.ChainHash, nil
		}
	}
	return nil, ErrUnknownSeq
}

func (f *fakeSource) Page(_ context.Context, after, through int64, limit int32) ([]Node, error) {
	f.pageCalls++
	if f.pageErr != nil {
		return nil, f.pageErr
	}
	var out []Node
	for _, n := range f.nodes {
		if n.Seq > after && n.Seq <= through && len(out) < int(limit) {
			out = append(out, n)
		}
	}
	return out, nil
}

func ledgerRecord(id string, seq int64) audit.LedgerRecord {
	blind := strings.Repeat("a", 64)
	ip := "203.0.113.7"
	return audit.LedgerRecord{
		ID: id, AccountRef: "11111111-2222-3333-4444-555555555555",
		IdentityBlindIndex: &blind, BlindIndexVersion: 1, EventType: "auth.login",
		ClientIP: &ip, Timestamp: proofTime.Add(time.Duration(seq) * time.Second),
		RetainUntil: proofTime.Add(8760 * time.Hour),
	}
}

// buildChain creates a well-formed ledger chain of n nodes with retained payloads.
func buildChain(t *testing.T, n int) *fakeSource {
	t.Helper()
	src := &fakeSource{chain: ChainLedger}
	prev := audit.LedgerGenesis()
	for i := 1; i <= n; i++ {
		rec := ledgerRecord("00000000-0000-4000-8000-00000000000"+string(rune('0'+i)), int64(i))
		leafHash, err := audit.LeafLedger(rec)
		if err != nil {
			t.Fatalf("LeafLedger: %v", err)
		}
		prev = audit.ChainLedger(prev, leafHash)
		src.nodes = append(src.nodes, Node{
			Seq: int64(i), LeafHash: leafHash.Bytes(), ChainHash: prev.Bytes(),
			Recompute: func() (audit.Digest, error) { return audit.LeafLedger(rec) },
		})
	}
	src.head = Head{Seq: int64(n), MaxSeq: int64(n), Hash: prev.Bytes()}
	return src
}

func verifyAll(t *testing.T, src *fakeSource, chain Chain) Result {
	t.Helper()
	params := Params{Chain: chain, Limit: 100}
	var last Result
	for {
		result, err := Verify(context.Background(), src, params)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		last = result
		next, ok := result.NextParams(params)
		if !ok {
			return last
		}
		params = next
	}
}

func TestVerifyIntactChain(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 5)
	result := verifyAll(t, src, ChainLedger)
	if !result.Verified || !result.Complete {
		t.Fatalf("verified=%v complete=%v reason=%v", result.Verified, result.Complete, result.FailureReason)
	}
	if result.Checked != 5 {
		t.Errorf("checked = %d, want 5", result.Checked)
	}
	if result.ErasedChecked != 0 {
		t.Errorf("erased_checked = %d, want 0", result.ErasedChecked)
	}
}

// TestVerifyAcceptsLawfullyErasedPayload is the core v2 property: the chain still
// verifies end to end after a retention purge, because the leaf digest survives.
func TestVerifyAcceptsLawfullyErasedPayload(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 5)
	op := "22222222-2222-4222-8222-222222222222"
	// Erase nodes 2 and 3: payload gone, leaf retained, erasure record present.
	for i := 1; i <= 2; i++ {
		src.nodes[i].Recompute = nil
		src.nodes[i].ErasureOperation = &op
	}

	result := verifyAll(t, src, ChainLedger)
	if !result.Verified || !result.Complete {
		t.Fatalf("an erased span broke verification: verified=%v reason=%v", result.Verified, result.FailureReason)
	}
	if result.Checked != 5 {
		t.Errorf("checked = %d, want 5", result.Checked)
	}
	if result.ErasedChecked != 2 {
		t.Errorf("erased_checked = %d, want 2", result.ErasedChecked)
	}
}

// TestVerifyRejectsUnexplainedMissingPayload is the check v1 structurally could
// not perform. A deletion that is not covered by an erasure record must be
// reported, not absorbed as retention.
func TestVerifyRejectsUnexplainedMissingPayload(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 4)
	src.nodes[2].Recompute = nil // payload gone, no erasure record

	result := verifyAll(t, src, ChainLedger)
	if result.Verified {
		t.Fatal("an unexplained missing payload verified clean")
	}
	if result.FailureReason == nil || *result.FailureReason != "payload_absent_without_erasure_record" {
		t.Errorf("failure reason = %v, want payload_absent_without_erasure_record", result.FailureReason)
	}
	if result.BrokenAtSeq == nil || *result.BrokenAtSeq != 3 {
		t.Errorf("broken_at_seq = %v, want 3", result.BrokenAtSeq)
	}
}

// TestVerifyRejectsRewrittenRetainedPayload proves the leaf still binds content.
func TestVerifyRejectsRewrittenRetainedPayload(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 3)
	rewritten := ledgerRecord("00000000-0000-4000-8000-000000000002", 2)
	other := "rewritten"
	rewritten.ClientID = &other
	src.nodes[1].Recompute = func() (audit.Digest, error) { return audit.LeafLedger(rewritten) }

	result := verifyAll(t, src, ChainLedger)
	if result.Verified {
		t.Fatal("a rewritten payload verified clean")
	}
	if result.FailureReason == nil || *result.FailureReason != "leaf_mismatch" {
		t.Errorf("failure reason = %v, want leaf_mismatch", result.FailureReason)
	}
	if result.ExpectedHash == nil || result.StoredHash == nil {
		t.Error("a leaf mismatch must report both digests so an operator can see the divergence")
	}
}

func TestVerifyRejectsNonLinkingNode(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 3)
	bogus := audit.LedgerGenesis()
	src.nodes[1].ChainHash = bogus.Bytes()

	result := verifyAll(t, src, ChainLedger)
	if result.Verified {
		t.Fatal("a non-linking node verified clean")
	}
	if result.FailureReason == nil || *result.FailureReason != "chain_mismatch" {
		t.Errorf("failure reason = %v, want chain_mismatch", result.FailureReason)
	}
}

// TestVerifyRejectsHeadMismatch closes the coherent-rewrite gap: a chain can be
// internally consistent and still not be the chain the head commits to.
func TestVerifyRejectsHeadMismatch(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 3)
	src.head.Hash = audit.LedgerGenesis().Bytes()

	result := verifyAll(t, src, ChainLedger)
	if result.Verified {
		t.Fatal("a chain that does not match its head verified clean")
	}
	if result.FailureReason == nil || *result.FailureReason != "head_mismatch" {
		t.Errorf("failure reason = %v, want head_mismatch", result.FailureReason)
	}
}

// TestVerifyDomainSeparation proves a ledger chain cannot be verified as an audit
// chain. Without distinct chaining domains a node could be replayed across chains.
func TestVerifyDomainSeparation(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 3)
	result, err := Verify(context.Background(), src, Params{Chain: ChainAudit, Limit: 100})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verified {
		t.Fatal("a ledger chain verified as an audit chain; the domains are interchangeable")
	}
}

func TestVerifyPaginates(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 7)
	params := Params{Chain: ChainLedger, Limit: 2}
	total := 0
	for {
		result, err := Verify(context.Background(), src, params)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !result.Verified {
			t.Fatalf("page failed: %v", result.FailureReason)
		}
		total += result.Checked
		next, ok := result.NextParams(params)
		if !ok {
			if !result.Complete {
				t.Fatal("traversal stopped without completing")
			}
			break
		}
		params = next
	}
	if total != 7 {
		t.Errorf("checked %d nodes across pages, want 7", total)
	}
	if src.pageCalls < 4 {
		t.Errorf("page calls = %d, want at least 4 for limit=2 over 7 nodes", src.pageCalls)
	}
}

// TestVerifyReportsSuppliedPredecessorMismatch keeps an operator-supplied seed
// from being trusted silently.
func TestVerifyReportsSuppliedPredecessorMismatch(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 3)
	wrong := audit.Genesis() // a real digest, but not this chain's node 1
	result, err := Verify(context.Background(), src, Params{
		Chain: ChainLedger, AfterSeq: 1, PredecessorHash: wrong.Bytes(), Limit: 10,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verified {
		t.Fatal("a mismatched supplied predecessor was accepted")
	}
	if result.FailureReason == nil || *result.FailureReason != "predecessor_mismatch" {
		t.Errorf("failure reason = %v, want predecessor_mismatch", result.FailureReason)
	}
	if result.SeedSource != "supplied_predecessor" {
		t.Errorf("seed source = %q, want supplied_predecessor", result.SeedSource)
	}
}

func TestVerifyRejectsMissingHead(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 2)
	src.head.Hash = nil
	if _, err := Verify(context.Background(), src, Params{Chain: ChainLedger, Limit: 10}); !errors.Is(err, ErrMissingHead) {
		t.Errorf("error = %v, want ErrMissingHead", err)
	}
}

func TestVerifyRejectsUnknownSeq(t *testing.T) {
	t.Parallel()

	src := buildChain(t, 3)
	_, err := Verify(context.Background(), src, Params{
		Chain: ChainLedger, AfterSeq: 99, ThroughSeq: 100, HasThrough: true, Limit: 10,
	})
	if !errors.Is(err, ErrUnknownSeq) {
		t.Errorf("error = %v, want ErrUnknownSeq", err)
	}
}

func TestVerifyRejectsUnknownChain(t *testing.T) {
	t.Parallel()

	if _, err := Verify(context.Background(), buildChain(t, 1), Params{Chain: "other"}); err == nil {
		t.Error("an unknown chain name was accepted")
	}
}

func TestVerifyRequiresSource(t *testing.T) {
	t.Parallel()

	if _, err := Verify(context.Background(), nil, Params{Chain: ChainLedger}); err == nil {
		t.Error("a nil source was accepted")
	}
}

func TestVerifyPropagatesSourceErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	for name, mutate := range map[string]func(*fakeSource){
		"head": func(f *fakeSource) { f.headErr = sentinel },
		"page": func(f *fakeSource) { f.pageErr = sentinel },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := buildChain(t, 2)
			mutate(src)
			if _, err := Verify(context.Background(), src, Params{Chain: ChainLedger, Limit: 10}); !errors.Is(err, sentinel) {
				t.Errorf("error = %v, want the source error", err)
			}
		})
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	t.Parallel()

	src := &fakeSource{chain: ChainLedger, head: Head{Seq: 0, MaxSeq: 0, Hash: audit.LedgerGenesis().Bytes()}}
	result, err := Verify(context.Background(), src, Params{Chain: ChainLedger, Limit: 10})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified || !result.Complete {
		t.Errorf("an empty initialized chain should verify complete, got verified=%v complete=%v", result.Verified, result.Complete)
	}
}

func TestVerifyRecordRoundTrip(t *testing.T) {
	t.Parallel()

	rec := ledgerRecord("00000000-0000-4000-8000-000000000001", 1)
	leafHash, err := audit.LeafLedger(rec)
	if err != nil {
		t.Fatalf("LeafLedger: %v", err)
	}
	if _, err := VerifyRecord(rec, leafHash.Bytes()); err != nil {
		t.Errorf("VerifyRecord on an intact record: %v", err)
	}

	other := "changed"
	tampered := rec
	tampered.Scope = &other
	if _, err := VerifyRecord(tampered, leafHash.Bytes()); err == nil {
		t.Error("VerifyRecord accepted a record that does not match its stored leaf")
	}
	if _, err := VerifyRecord(rec, []byte{0x01}); err == nil {
		t.Error("VerifyRecord accepted a malformed stored leaf")
	}
}
