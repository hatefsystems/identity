package ledgerproof

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

type memorySource struct {
	head         Head
	steps        []Step
	headErr      error
	pageErr      error
	boundaryErr  error
	pageLimit    int32
	dropPageTail bool
}

func fixture(seqs ...int64) *memorySource {
	s := &memorySource{head: Head{Hash: genesis()}}
	prev := audit.GenesisChainHash
	for _, seq := range seqs {
		record := audit.LedgerRecord{ID: fmt.Sprint(seq), AccountRef: "private-subject",
			EventType: "private-event", ClientIP: ptr("192.0.2.123"), Timestamp: time.Unix(seq, 123000),
			RetainUntil: time.Unix(seq, 123000).Add(8760 * time.Hour)}
		hash := audit.ChainHash(prev, audit.SerializeLedger(record))
		s.steps = append(s.steps, Step{Checkpoint: Checkpoint{FirstSeq: seq, LastSeq: seq, TerminalHash: hash}, Record: &record})
		s.head = Head{Seq: seq, MaxSeq: seq, Hash: hash}
		prev, _ = audit.DecodeChainHash(hash)
	}
	return s
}

func (s *memorySource) erase(first, last int) {
	before := Checkpoint{TerminalHash: genesis()}
	if first > 0 {
		before = s.steps[first-1].Checkpoint
	}
	count := int64(0)
	for _, step := range s.steps[first : last+1] {
		if step.Record == nil {
			count += step.ErasedCount
		} else {
			count++
		}
	}
	span := Step{Checkpoint: Checkpoint{FirstSeq: s.steps[first].FirstSeq, LastSeq: s.steps[last].LastSeq,
		PredecessorSeq: before.LastSeq, PredecessorHash: before.TerminalHash,
		TerminalHash: s.steps[last].TerminalHash, ErasedCount: count}}
	s.steps = slices.Replace(s.steps, first, last+1, span)
}

func (s *memorySource) Head(context.Context) (Head, error) { return s.head, s.headErr }
func (s *memorySource) Boundary(_ context.Context, seq int64) ([]Step, error) {
	var result []Step
	for _, step := range s.steps {
		if step.FirstSeq <= seq && step.LastSeq >= seq || step.Record == nil && step.PredecessorSeq == seq {
			result = append(result, step)
		}
	}
	return result, s.boundaryErr
}
func (s *memorySource) Page(_ context.Context, after, through int64, limit int32) ([]Step, error) {
	s.pageLimit = limit
	var result []Step
	for _, step := range s.steps {
		if step.LastSeq > after && step.FirstSeq <= through {
			result = append(result, step)
			if len(result) == int(limit) {
				break
			}
		}
	}
	if s.dropPageTail && len(result) > 0 {
		result = result[:len(result)-1]
	}
	return result, s.pageErr
}

func TestVerifyRetentionShapesAndAllocationGaps(t *testing.T) {
	for _, test := range []struct {
		name           string
		mutate         func(*memorySource)
		checked, spans int
		purged         int64
	}{
		{"intact", func(*memorySource) {}, 7, 0, 0},
		{"prefix", func(s *memorySource) { s.erase(0, 1) }, 5, 1, 2},
		{"interior", func(s *memorySource) { s.erase(2, 4) }, 4, 1, 3},
		{"tail", func(s *memorySource) { s.erase(5, 6) }, 5, 1, 2},
		{"held islands", func(s *memorySource) { s.erase(5, 6); s.erase(2, 3); s.erase(0, 0) }, 2, 3, 5},
		{"all purged", func(s *memorySource) { s.erase(0, 6) }, 0, 1, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := fixture(2, 8, 11, 18, 19, 27, 35)
			test.mutate(s)
			r, err := Verify(context.Background(), s, Params{Limit: 20})
			if err != nil || r.Verified != (test.checked > 0) || !r.Complete || r.Checked != test.checked || r.PurgedSpans != test.spans || r.PurgedCount != test.purged || r.ProofSteps != test.checked+test.spans || r.ThroughSeq != 35 || r.LastHash == nil || *r.LastHash != s.head.Hash || r.NextAfterSeq != nil {
				t.Fatalf("result=%+v error=%v", r, err)
			}
			if test.checked == 0 && (r.FailureReason == nil || *r.FailureReason != "no_retained_records" || r.BrokenAtSeq != nil) {
				t.Fatalf("erasure treated as content proof or tampering: %+v", r)
			}
		})
	}
}

func TestVerifyBoundedMixedPaginationAndFixedWatermark(t *testing.T) {
	s := fixture(1, 4, 9, 12, 18, 30)
	s.erase(4, 5)
	s.erase(0, 1)
	p := Params{Limit: 1}
	checked, purged, pages := 0, int64(0), 0
	for {
		r, err := Verify(context.Background(), s, p)
		if err != nil || r.ProofSteps > 1 || s.pageLimit != 2 || r.ThroughSeq != 30 || r.RestartRequired {
			t.Fatalf("page=%+v err=%v requested=%d", r, err, s.pageLimit)
		}
		checked += r.Checked
		purged += r.PurgedCount
		pages++
		if pages > 4 {
			t.Fatal("unbounded pagination")
		}
		if r.NextAfterSeq == nil {
			if !r.Complete {
				t.Fatalf("incomplete: %+v", r)
			}
			break
		}
		p = Params{AfterSeq: *r.NextAfterSeq, ThroughSeq: r.ThroughSeq, HasThrough: true, PredecessorHash: *r.LastHash, Limit: 1}
		if pages == 1 {
			prev, _ := audit.DecodeChainHash(s.head.Hash)
			record := audit.LedgerRecord{ID: "later append"}
			hash := audit.ChainHash(prev, audit.SerializeLedger(record))
			s.steps = append(s.steps, Step{Checkpoint: Checkpoint{FirstSeq: 44, LastSeq: 44, TerminalHash: hash}, Record: &record})
			s.head = Head{Seq: 44, MaxSeq: 44, Hash: hash}
		}
	}
	if checked != 2 || purged != 4 || pages != 4 {
		t.Fatalf("checked=%d purged=%d pages=%d", checked, purged, pages)
	}
}

func TestVerifyExactBoundariesAndCompaction(t *testing.T) {
	s := fixture(1, 4, 9, 12, 18)
	first, err := Verify(context.Background(), s, Params{Limit: 2})
	if err != nil || first.LastHash == nil {
		t.Fatal(err)
	}
	s.erase(0, 1)
	p := Params{AfterSeq: 4, ThroughSeq: 18, HasThrough: true, PredecessorHash: *first.LastHash, Limit: 20}
	r, err := Verify(context.Background(), s, p)
	if err != nil || !r.Verified || !r.Complete || r.Checked != 3 {
		t.Fatalf("exact terminal lost: %+v %v", r, err)
	}
	s.erase(0, 1) // Compaction absorbs seq 9 and destroys the interior seq 4 digest.
	r, err = Verify(context.Background(), s, p)
	if err != nil || !r.RestartRequired || r.Verified || r.Complete || r.NextAfterSeq != nil || r.BrokenAtSeq != nil || *r.FailureReason != "retention_boundary_unavailable" {
		t.Fatalf("invented seed: %+v %v", r, err)
	}
	r, err = Verify(context.Background(), s, Params{ThroughSeq: 4, HasThrough: true, Limit: 20})
	if err != nil || !r.RestartRequired || r.ThroughSeq != 4 {
		t.Fatalf("moved watermark: %+v %v", r, err)
	}
	r, err = Verify(context.Background(), s, Params{Limit: 20})
	if err != nil || !r.Verified || !r.Complete || r.Checked != 2 || r.PurgedCount != 3 {
		t.Fatalf("restart failed: %+v %v", r, err)
	}
}

func TestVerifyCheckpointPredecessorBoundary(t *testing.T) {
	s := fixture(1, 4, 9)
	s.erase(1, 2)
	// The predecessor digest is also represented by the following span. Its
	// presence never implies that erased bodies have been recomputed.
	r, err := Verify(context.Background(), s, Params{AfterSeq: 1, ThroughSeq: 9, HasThrough: true, Limit: 10})
	if err != nil || r.SeedSource != "checkpoint_boundary" || !r.Complete || r.Verified || r.PurgedCount != 2 {
		t.Fatalf("exact predecessor: %+v %v", r, err)
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		mutate       func(*memorySource)
		params       Params
	}{
		{"uninitialized", "missing_head", func(s *memorySource) { s.headErr = ErrMissingHead }, Params{}},
		{"missing prefix", "hash_mismatch", func(s *memorySource) { s.steps = s.steps[1:] }, Params{}},
		{"missing interior", "hash_mismatch", func(s *memorySource) { s.steps = append(s.steps[:1], s.steps[2:]...) }, Params{}},
		{"lost tail", "head_mismatch", func(s *memorySource) { s.steps = s.steps[:2]; s.head.MaxSeq = 4 }, Params{}},
		{"stale head", "head_mismatch", func(s *memorySource) { s.head.Seq = 4 }, Params{}},
		{"altered head", "head_mismatch", func(s *memorySource) { s.head.Hash = strings.Repeat("b", 64) }, Params{}},
		{"malformed head", "head_mismatch", func(s *memorySource) { s.head.Hash = "bad" }, Params{}},
		{"reset sequence", "head_mismatch", func(s *memorySource) { s.head.Seq = 0 }, Params{}},
		{"altered body", "hash_mismatch", func(s *memorySource) { s.steps[1].Record.EventType = "rewritten" }, Params{}},
		{"bad predecessor", "checkpoint_link_mismatch", func(s *memorySource) { s.erase(1, 1); s.steps[1].PredecessorHash = strings.Repeat("b", 64) }, Params{}},
		{"wrong predecessor seq", "checkpoint_link_mismatch", func(s *memorySource) { s.erase(1, 1); s.steps[1].PredecessorSeq = 2 }, Params{}},
		{"malformed checkpoint", "invalid_checkpoint", func(s *memorySource) { s.erase(1, 1); s.steps[1].TerminalHash = "bad" }, Params{}},
		{"invalid count", "invalid_checkpoint", func(s *memorySource) { s.erase(1, 1); s.steps[1].ErasedCount = 2 }, Params{}},
		{"overlap", "checkpoint_overlap", func(s *memorySource) { s.erase(1, 1); s.steps[1].Problem = "checkpoint_overlap" }, Params{}},
		{"missing span predecessor", "checkpoint_link_mismatch", func(s *memorySource) { s.erase(1, 1); s.steps[1].Problem = "checkpoint_link_mismatch" }, Params{}},
		{"supplied mismatch", "predecessor_mismatch", func(*memorySource) {}, Params{AfterSeq: 1, ThroughSeq: 9, HasThrough: true, PredecessorHash: strings.Repeat("a", 64)}},
		{"purged supplied mismatch", "predecessor_mismatch", func(s *memorySource) { s.erase(0, 0) }, Params{AfterSeq: 1, ThroughSeq: 9, HasThrough: true, PredecessorHash: strings.Repeat("a", 64)}},
		{"lost upper proof", "missing_proof", func(s *memorySource) { s.dropPageTail = true }, Params{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := fixture(1, 4, 9)
			test.mutate(s)
			p := test.params
			p.Limit = 10
			r, err := Verify(context.Background(), s, p)
			if err != nil || r.Verified || r.Complete || r.NextAfterSeq != nil || r.FailureReason == nil || *r.FailureReason != test.reason {
				t.Fatalf("false proof: %+v err=%v want=%s", r, err, test.reason)
			}
		})
	}
}

func TestVerifyEmptyAndInvalidRequests(t *testing.T) {
	r, err := Verify(context.Background(), fixture(), Params{Limit: 1})
	if err != nil || r.Verified || !r.Complete || r.FailureReason == nil || *r.FailureReason != "no_retained_records" {
		t.Fatalf("empty initialized: %+v %v", r, err)
	}
	for _, p := range []Params{{Limit: 0}, {Limit: 5001}, {Limit: 1, AfterSeq: -1}, {Limit: 1, AfterSeq: 1}, {Limit: 1, ThroughSeq: -1}, {Limit: 1, HasThrough: true, AfterSeq: 2, ThroughSeq: 1}, {Limit: 1, PredecessorHash: "bad"}} {
		if _, err := Verify(context.Background(), fixture(1, 4, 9), p); err == nil {
			t.Fatalf("accepted invalid params %+v", p)
		}
	}
	for _, p := range []Params{{AfterSeq: 2, ThroughSeq: 9, HasThrough: true, Limit: 1}, {ThroughSeq: 2, HasThrough: true, Limit: 1}} {
		if _, err := Verify(context.Background(), fixture(1, 4, 9), p); err == nil || !strings.HasPrefix(err.Error(), "unknown_") {
			t.Fatalf("approximated unknown boundary %+v: %v", p, err)
		}
	}
}

func TestVerifySourceErrorsAndLegacyPrecision(t *testing.T) {
	failure := errors.New("database unavailable")
	for _, mutate := range []func(*memorySource){func(s *memorySource) { s.headErr = failure }, func(s *memorySource) { s.boundaryErr = failure }, func(s *memorySource) { s.pageErr = failure }} {
		s := fixture(1)
		mutate(s)
		if _, err := Verify(context.Background(), s, Params{Limit: 1}); !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
	s := fixture(1)
	record := s.steps[0].Record
	record.Timestamp = record.Timestamp.Add(789 * time.Nanosecond)
	oldHash := audit.ChainHash(audit.GenesisChainHash, audit.SerializeLedger(*record))
	s.steps[0].TerminalHash, s.head.Hash = oldHash, oldHash
	record.Timestamp = record.Timestamp.Truncate(time.Microsecond)
	r, err := Verify(context.Background(), s, Params{Limit: 1})
	if err != nil || r.Verified || r.Checked != 1 || r.FailureReason == nil || *r.FailureReason != "hash_mismatch" || s.head.Hash != oldHash {
		t.Fatalf("legacy hash repaired: %+v %v", r, err)
	}
}

func TestCheckpointValidation(t *testing.T) {
	valid := Checkpoint{FirstSeq: 2, LastSeq: 20, PredecessorSeq: 1, PredecessorHash: strings.Repeat("1", 64), TerminalHash: strings.Repeat("2", 64), ErasedCount: 2}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Checkpoint){
		func(c *Checkpoint) { c.FirstSeq = 0 }, func(c *Checkpoint) { c.LastSeq = 1 }, func(c *Checkpoint) { c.PredecessorSeq = 2 },
		func(c *Checkpoint) { c.PredecessorSeq = -1 }, func(c *Checkpoint) { c.ErasedCount = 0 }, func(c *Checkpoint) { c.ErasedCount = 20 },
		func(c *Checkpoint) { c.ErasedCount = 1 }, func(c *Checkpoint) { c.PredecessorSeq = 0 }, func(c *Checkpoint) { c.TerminalHash = strings.Repeat("A", 64) },
	} {
		c := valid
		mutate(&c)
		if c.Validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
