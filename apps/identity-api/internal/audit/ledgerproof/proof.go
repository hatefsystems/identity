// Package ledgerproof verifies database-relative retained ledger segments.
// Checkpoints preserve boundary digests, not the erased bodies or an external
// trust anchor. All Source reads must belong to the same database snapshot.
package ledgerproof

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strings"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// Head is the initialized logical tip and the greatest live/checkpoint sequence.
type Head struct {
	Seq, MaxSeq int64
	Hash        string
}

// Checkpoint is one authorized erased span in committed chain order.
type Checkpoint struct {
	FirstSeq, LastSeq, PredecessorSeq, ErasedCount int64
	PredecessorHash, TerminalHash                  string
}

// Validate checks shape, including allocation gaps without inventing row counts.
func (c Checkpoint) Validate() error {
	if c.FirstSeq <= 0 || c.LastSeq < c.FirstSeq || c.PredecessorSeq < 0 || c.PredecessorSeq >= c.FirstSeq ||
		c.ErasedCount <= 0 || c.ErasedCount > c.LastSeq-c.FirstSeq+1 ||
		(c.FirstSeq != c.LastSeq && c.ErasedCount < 2) || !validHash(c.PredecessorHash) || !validHash(c.TerminalHash) ||
		(c.PredecessorSeq == 0 && c.PredecessorHash != genesis()) {
		return errors.New("invalid_checkpoint")
	}
	return nil
}

// VerifyRecord recomputes a retained body with the signer's canonical format.
func VerifyRecord(predecessor string, record audit.LedgerRecord, stored string) (string, error) {
	prev, err := audit.DecodeChainHash(predecessor)
	if err != nil {
		return "", err
	}
	expected := audit.ChainHash(prev, audit.SerializeLedger(record))
	if expected != stored {
		return expected, errors.New("hash_mismatch")
	}
	return expected, nil
}

// Step is a live record or an erased span. Problem reports local structural
// checks by the source (overlap or a checkpoint's missing exact predecessor).
type Step struct {
	Checkpoint
	Record  *audit.LedgerRecord
	Problem string
}

// Source returns bounded proof nodes and exact boundary candidates. Boundary
// includes covering checkpoints so an interior compacted digest is distinguished
// from an unknown sequence. Page includes one lookahead node in its limit.
type Source interface {
	Head(context.Context) (Head, error)
	Boundary(context.Context, int64) ([]Step, error)
	Page(context.Context, int64, int64, int32) ([]Step, error)
}

// ErrMissingHead distinguishes uninitialized proof state from an empty ledger.
var ErrMissingHead = errors.New("missing_head")

// Params fixes the scan watermark for continuation requests.
type Params struct {
	AfterSeq, ThroughSeq int64
	HasThrough           bool
	PredecessorHash      string
	Limit                int32
}

// Result contains no ledger contents or subject identifiers. Checked counts
// recomputed records only; ProofSteps also counts authorized erased spans.
type Result struct {
	AfterSeq, ThroughSeq                int64
	SeedHash, SeedSource                string
	Verified, Complete, RestartRequired bool
	Checked, PurgedSpans, ProofSteps    int
	PurgedCount                         int64
	FirstSeq, LastSeq, NextAfterSeq     *int64
	BrokenAtSeq                         *int64
	ExpectedHash, StoredHash, LastHash  *string
	FailureReason                       *string
}

// Verify traverses one bounded page. A no-content page can still have a next
// cursor or complete proof traversal, but never reports Verified=true.
func Verify(ctx context.Context, source Source, p Params) (Result, error) {
	r := Result{AfterSeq: p.AfterSeq, ThroughSeq: p.ThroughSeq, SeedHash: genesis(), SeedSource: "genesis"}
	if p.Limit < 1 || p.Limit > 5000 || p.AfterSeq < 0 || p.ThroughSeq < 0 || (p.HasThrough && p.AfterSeq > p.ThroughSeq) || (p.AfterSeq > 0 && !p.HasThrough) {
		return r, errors.New("invalid_request")
	}
	head, err := source.Head(ctx)
	if errors.Is(err, ErrMissingHead) {
		return fail(r, "missing_head", nil), nil
	}
	if err != nil {
		return r, err
	}
	if !p.HasThrough {
		p.ThroughSeq, r.ThroughSeq = head.Seq, head.Seq
	}
	if head.Seq < 0 || head.Seq != head.MaxSeq || !validHash(head.Hash) || (head.Seq == 0 && head.Hash != genesis()) || p.ThroughSeq > head.Seq {
		return fail(r, "head_mismatch", nil), nil
	}
	// Even a historical page must not conceal a lost tail or sequence reset.
	if head.Seq > 0 {
		hash, _, reason, err := boundary(ctx, source, head.Seq)
		if err != nil {
			return r, err
		}
		if reason != "" {
			if reason == "missing_proof" || reason == "retention_boundary_unavailable" {
				reason = "head_mismatch"
			}
			return fail(r, reason, &head.Seq), nil
		}
		if hash != head.Hash {
			return fail(r, "head_mismatch", &head.Seq), nil
		}
	}
	throughHash := genesis()
	if p.ThroughSeq > 0 {
		var reason string
		throughHash, _, reason, err = boundary(ctx, source, p.ThroughSeq)
		if err != nil {
			return r, err
		}
		if reason != "" {
			if reason == "missing_proof" {
				return r, errors.New("unknown_through_seq")
			}
			return fail(r, reason, &p.ThroughSeq), nil
		}
	}
	if p.AfterSeq > 0 {
		var reason string
		r.SeedHash, r.SeedSource, reason, err = boundary(ctx, source, p.AfterSeq)
		if err != nil {
			return r, err
		}
		if reason != "" {
			if reason == "missing_proof" {
				return r, errors.New("unknown_after_seq")
			}
			return fail(r, reason, &p.AfterSeq), nil
		}
	}
	if p.PredecessorHash != "" {
		if !validHash(strings.ToLower(p.PredecessorHash)) {
			return r, errors.New("invalid_request")
		}
		stored := r.SeedHash
		r.SeedHash, r.SeedSource = strings.ToLower(p.PredecessorHash), "supplied_predecessor"
		if r.SeedHash != stored {
			r.ExpectedHash, r.StoredHash = &r.SeedHash, &stored
			return fail(r, "predecessor_mismatch", &p.AfterSeq), nil
		}
	}
	steps, err := source.Page(ctx, p.AfterSeq, p.ThroughSeq, p.Limit+1)
	if err != nil {
		return r, err
	}
	if len(steps) > int(p.Limit)+1 {
		return fail(r, "invalid_checkpoint", nil), nil
	}
	hasMore := len(steps) > int(p.Limit)
	lastSeq, lastHash := p.AfterSeq, r.SeedHash
	for i, step := range steps {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if problem := validateStep(step); problem != "" {
			return fail(r, problem, &step.FirstSeq), nil
		}
		if step.FirstSeq <= lastSeq || step.LastSeq > p.ThroughSeq {
			return fail(r, "checkpoint_overlap", &step.FirstSeq), nil
		}
		// Validate the lookahead's boundary too; it may overlap the final span.
		if step.Record == nil && (step.PredecessorSeq != lastSeq || step.PredecessorHash != lastHash) {
			return fail(r, "checkpoint_link_mismatch", &step.FirstSeq), nil
		}
		if i == int(p.Limit) {
			break
		}
		if r.FirstSeq == nil {
			r.FirstSeq = ptr(step.FirstSeq)
		}
		r.ProofSteps++
		if step.Record != nil {
			r.Checked++
			expected, hashErr := VerifyRecord(lastHash, *step.Record, step.TerminalHash)
			if hashErr != nil {
				r.LastSeq = ptr(step.LastSeq)
				r.ExpectedHash, r.StoredHash = &expected, &step.TerminalHash
				return fail(r, "hash_mismatch", &step.FirstSeq), nil
			}
		} else {
			if step.ErasedCount > math.MaxInt64-r.PurgedCount {
				return fail(r, "invalid_checkpoint", &step.FirstSeq), nil
			}
			r.PurgedSpans++
			r.PurgedCount += step.ErasedCount
		}
		lastSeq, lastHash = step.LastSeq, step.TerminalHash
		r.LastSeq, r.LastHash = ptr(lastSeq), ptr(lastHash)
	}
	if hasMore {
		r.NextAfterSeq = ptr(lastSeq)
	} else if lastSeq != p.ThroughSeq || lastHash != throughHash {
		return fail(r, "missing_proof", nil), nil
	} else {
		r.Complete = true
	}
	if r.Checked == 0 {
		r.FailureReason = ptr("no_retained_records")
	} else {
		r.Verified = true
	}
	return r, nil
}

func boundary(ctx context.Context, source Source, seq int64) (hash, seed, reason string, err error) {
	steps, err := source.Boundary(ctx, seq)
	if err != nil {
		return "", "", "", err
	}
	if len(steps) > 3 {
		return "", "", "checkpoint_overlap", nil
	}
	covered := false
	for _, step := range steps {
		if problem := validateStep(step); problem != "" {
			return "", "", problem, nil
		}
		candidate, source := "", "checkpoint_boundary"
		switch {
		case step.LastSeq == seq:
			candidate = step.TerminalHash
			if step.Record != nil {
				source = "database_predecessor"
			}
		case step.Record == nil && step.PredecessorSeq == seq:
			candidate = step.PredecessorHash
		case step.FirstSeq <= seq && seq < step.LastSeq:
			covered = true
		}
		if candidate != "" {
			if hash != "" && candidate != hash {
				return "", "", "checkpoint_link_mismatch", nil
			}
			hash, seed = candidate, source
		}
	}
	if covered {
		if hash != "" {
			return "", "", "checkpoint_overlap", nil
		}
		return "", "", "retention_boundary_unavailable", nil
	}
	if hash == "" {
		return "", "", "missing_proof", nil
	}
	return hash, seed, "", nil
}

func validateStep(step Step) string {
	if step.Problem != "" {
		return step.Problem
	}
	if step.Record != nil {
		if step.FirstSeq <= 0 || step.FirstSeq != step.LastSeq || step.ErasedCount != 0 || !validHash(step.TerminalHash) {
			return "missing_proof"
		}
	} else if err := step.Validate(); err != nil {
		return "invalid_checkpoint"
	}
	return ""
}

func fail(r Result, reason string, seq *int64) Result {
	r.Verified, r.Complete, r.NextAfterSeq = false, false, nil
	r.FailureReason = &reason
	r.RestartRequired = reason == "retention_boundary_unavailable"
	if !r.RestartRequired {
		r.BrokenAtSeq = seq
	}
	return r
}

func validHash(hash string) bool {
	_, err := audit.DecodeChainHash(hash)
	return err == nil && hash == strings.ToLower(hash)
}

func genesis() string   { return hex.EncodeToString(audit.GenesisChainHash[:]) }
func ptr[T any](v T) *T { return &v }
