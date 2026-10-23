// Package ledgerproof verifies either cryptographic chain.
//
// # What v2 verification proves
//
// Under canonical format v2 each chain lives in its own append-only table, one
// node per record, holding a leaf digest and a chain digest. Verification walks
// those nodes in seq order and checks three things:
//
//   - every node links: chain_hash(N) == SHA-256(prefix || chain_hash(N-1) || leaf_hash(N));
//   - every retained payload reproduces its node's leaf digest;
//   - every absent payload is covered by an erasure record.
//
// The third check is new. In v1 an erased record left a hole in the chain, so
// verification had to bridge it using predecessor/terminal digests stored in a
// checkpoint table, and compaction of adjacent spans meant the bridge itself was
// rewritten over time. The consequence was that "payload missing" could only be
// tolerated, never judged: a lawful erasure and a malicious deletion were the same
// observation. Now the chain is never broken, so an absent payload is a positive
// claim that must be authorized, and an unauthorized one is reported as tampering.
//
// # Why one implementation serves both chains
//
// Both chains have the same shape after the split, so they are verified by this
// one walker rather than by two handlers that could drift apart. The only
// per-chain differences are the domain prefix, the genesis seed, and how a payload
// row is projected back onto its canonical record — all supplied by the caller.
package ledgerproof

import (
	"context"
	"errors"
	"fmt"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// Chain selects which of the two chains is being verified.
type Chain string

const (
	// ChainAudit is the Class C audit log chain.
	ChainAudit Chain = "audit"
	// ChainLedger is the Class B security event ledger chain.
	ChainLedger Chain = "ledger"
)

// Genesis returns the chain's genesis predecessor digest.
func (c Chain) Genesis() audit.Digest {
	if c == ChainAudit {
		return audit.Genesis()
	}
	return audit.LedgerGenesis()
}

// Link applies the chain's own chaining step, so a digest from one chain can
// never be produced in the other's domain.
func (c Chain) Link(prev, leafHash audit.Digest) audit.Digest {
	if c == ChainAudit {
		return audit.ChainAudit(prev, leafHash)
	}
	return audit.ChainLedger(prev, leafHash)
}

// Head is a chain's durable logical tip plus the highest position that exists.
// MaxSeq comes from the chain table, which is never deleted, so unlike v1 it
// cannot be depressed by retention.
type Head struct {
	Seq    int64
	MaxSeq int64
	Hash   []byte
}

// Node is one chain node and, when retained, a way to recompute its leaf.
type Node struct {
	Seq       int64
	LeafHash  []byte
	ChainHash []byte
	// Recompute derives the leaf digest from the retained payload. It is nil when
	// the payload has been erased.
	Recompute func() (audit.Digest, error)
	// ErasureOperation is non-nil when an erasure record covers this node. It is
	// what distinguishes a lawful erasure from a deletion.
	ErasureOperation *string
}

// Source supplies head and nodes.
type Source interface {
	Head(ctx context.Context) (Head, error)
	Page(ctx context.Context, after, through int64, limit int32) ([]Node, error)
	// HashAt returns the stored chain digest at an exact seq, or a not-found
	// error. Exactness matters: gaps are legal, so "at or after" would hand
	// verification a later node's digest and report a break in an intact chain.
	HashAt(ctx context.Context, seq int64) ([]byte, error)
}

// ErrMissingHead reports an uninitialized head. It is deliberately not treated as
// genesis: an uninitialized head and a genuinely empty chain are different states,
// and conflating them is how a verifier blesses a chain that was restarted.
var ErrMissingHead = errors.New("missing_head")

// ErrUnknownSeq reports a caller-named seq that does not exist.
var ErrUnknownSeq = errors.New("unknown_seq")

// Params bounds one verification pass.
type Params struct {
	Chain Chain
	// AfterSeq starts the walk; 0 means genesis.
	AfterSeq int64
	// PredecessorHash optionally overrides the seed with an operator-supplied
	// digest. It is reported as a mismatch rather than trusted silently.
	PredecessorHash []byte
	// ThroughSeq caps the walk when HasThrough is set.
	ThroughSeq int64
	HasThrough bool
	// Limit bounds one page.
	Limit int32
}

// Result reports one pass. Hash fields are hex for direct JSON use.
type Result struct {
	Chain      string
	Verified   bool
	Complete   bool
	Checked    int
	AfterSeq   int64
	ThroughSeq int64
	SeedHash   string
	SeedSource string
	FirstSeq   *int64
	LastSeq    *int64
	LastHash   string
	// lastDigest is the raw form of LastHash, used to seed the next page without
	// a hex round trip.
	lastDigest   audit.Digest
	NextAfterSeq *int64
	// ErasedChecked counts nodes whose payload was absent but lawfully erased.
	ErasedChecked int
	BrokenAtSeq   *int64
	ExpectedHash  *string
	StoredHash    *string
	FailureReason *string
}

const defaultLimit = 1000

// Verify walks one page of a chain.
func Verify(ctx context.Context, source Source, p Params) (Result, error) {
	if source == nil {
		return Result{}, errors.New("ledgerproof: source is required")
	}
	if p.Chain != ChainAudit && p.Chain != ChainLedger {
		return Result{}, errors.New("ledgerproof: unknown chain")
	}
	limit := p.Limit
	if limit <= 0 {
		limit = defaultLimit
	}

	head, err := source.Head(ctx)
	if err != nil {
		return Result{}, err
	}
	if len(head.Hash) != audit.DigestSize {
		return Result{}, ErrMissingHead
	}

	through := head.MaxSeq
	if p.HasThrough {
		through = p.ThroughSeq
		// An explicit upper boundary must still exist, or a completed proof could
		// be claimed over a tail that has disappeared between pages.
		if through > 0 {
			if _, err := source.HashAt(ctx, through); err != nil {
				return Result{}, err
			}
		}
	}

	result := Result{
		Chain: string(p.Chain), Verified: true, AfterSeq: p.AfterSeq, ThroughSeq: through,
		SeedSource: "genesis",
	}

	// Seed the predecessor. after_seq == 0 starts at genesis, which is chained
	// like any other node so there is no special case to forge a new "first"
	// record against.
	previous := p.Chain.Genesis()
	if p.AfterSeq > 0 {
		stored, seedErr := source.HashAt(ctx, p.AfterSeq)
		if seedErr != nil {
			return Result{}, seedErr
		}
		previous, err = audit.DecodeDigest(stored)
		if err != nil {
			return Result{}, fmt.Errorf("ledgerproof: stored digest at seq %d: %w", p.AfterSeq, err)
		}
		result.SeedSource = "database_predecessor"
	}
	storedSeed := previous.Hex()

	seedMismatch := false
	if len(p.PredecessorHash) > 0 {
		supplied, decodeErr := audit.DecodeDigest(p.PredecessorHash)
		if decodeErr != nil {
			return Result{}, decodeErr
		}
		seedMismatch = supplied != previous
		previous = supplied
		result.SeedSource = "supplied_predecessor"
	}
	result.SeedHash = previous.Hex()
	result.LastHash, result.lastDigest = result.SeedHash, previous

	if seedMismatch {
		result.Verified = false
		result.FailureReason = ptr("predecessor_mismatch")
		result.BrokenAtSeq = ptr(p.AfterSeq)
		result.ExpectedHash, result.StoredHash = ptr(result.SeedHash), ptr(storedSeed)
		return result, nil
	}
	if p.AfterSeq >= through {
		result.Complete = true
		return result, nil
	}

	nodes, err := source.Page(ctx, p.AfterSeq, through, limit)
	if err != nil {
		return Result{}, err
	}
	if len(nodes) == 0 {
		result.Verified = false
		result.FailureReason = ptr("no_stored_records")
		return result, nil
	}

	cursor := p.AfterSeq
	for i, node := range nodes {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if node.Seq <= cursor || node.Seq > through {
			return Result{}, fmt.Errorf("ledgerproof: node seq %d outside (%d, %d]", node.Seq, cursor, through)
		}
		leafHash, err := audit.DecodeDigest(node.LeafHash)
		if err != nil {
			return failAt(result, "invalid_leaf_hash", node.Seq), nil
		}
		storedChain, err := audit.DecodeDigest(node.ChainHash)
		if err != nil {
			return failAt(result, "invalid_chain_hash", node.Seq), nil
		}
		if i == 0 {
			result.FirstSeq = ptr(node.Seq)
		}
		result.Checked++
		result.LastSeq = ptr(node.Seq)

		// 1. Linkage.
		expected := p.Chain.Link(previous, leafHash)
		if expected != storedChain {
			out := failAt(result, "chain_mismatch", node.Seq)
			out.ExpectedHash, out.StoredHash = ptr(expected.Hex()), ptr(storedChain.Hex())
			return out, nil
		}

		switch {
		// 2. A retained payload must reproduce the leaf.
		case node.Recompute != nil:
			recomputed, err := node.Recompute()
			if err != nil {
				return failAt(result, "record_not_serializable", node.Seq), nil
			}
			if recomputed != leafHash {
				out := failAt(result, "leaf_mismatch", node.Seq)
				out.ExpectedHash, out.StoredHash = ptr(recomputed.Hex()), ptr(leafHash.Hex())
				return out, nil
			}
		// 3. An absent payload must be authorized by an erasure record.
		case node.ErasureOperation == nil:
			return failAt(result, "payload_absent_without_erasure_record", node.Seq), nil
		default:
			result.ErasedChecked++
		}

		previous = storedChain
		cursor = node.Seq
	}

	result.LastHash, result.lastDigest = previous.Hex(), previous
	result.NextAfterSeq = ptr(cursor)
	result.Complete = cursor >= through

	if result.Complete && !p.HasThrough {
		// The walk reached the chain's end, so the digest it arrived at must be the
		// digest the head commits to. Without this the verifier would accept a
		// chain that is internally consistent but is not the one the head names —
		// which is exactly what a coherent rewrite produces.
		expected, err := audit.DecodeDigest(head.Hash)
		if err != nil {
			return Result{}, ErrMissingHead
		}
		if head.Seq != cursor || previous != expected {
			out := failAt(result, "head_mismatch", cursor)
			out.ExpectedHash, out.StoredHash = ptr(previous.Hex()), ptr(expected.Hex())
			return out, nil
		}
	}
	return result, nil
}

// NextParams builds the continuation for a partially completed pass, carrying the
// digest forward without a hex round trip.
func (r Result) NextParams(p Params) (Params, bool) {
	if r.Complete || r.NextAfterSeq == nil || !r.Verified {
		return Params{}, false
	}
	p.AfterSeq = *r.NextAfterSeq
	p.PredecessorHash = r.lastDigest.Bytes()
	return p, true
}

func failAt(r Result, reason string, seq int64) Result {
	r.Verified = false
	r.Complete = false
	r.FailureReason = &reason
	r.BrokenAtSeq = &seq
	return r
}

func ptr[T any](v T) *T { return &v }

// VerifyRecord recomputes one ledger record's leaf digest and compares it to the
// stored value. It is the single-record form used by the signer's smoke probe.
func VerifyRecord(record audit.LedgerRecord, storedLeaf []byte) ([]byte, error) {
	leafHash, err := audit.LeafLedger(record)
	if err != nil {
		return nil, fmt.Errorf("ledgerproof: serialize record: %w", err)
	}
	stored, err := audit.DecodeDigest(storedLeaf)
	if err != nil {
		return nil, err
	}
	if leafHash != stored {
		return nil, fmt.Errorf("ledgerproof: leaf mismatch: recomputed %s, stored %s", leafHash.Hex(), stored.Hex())
	}
	return leafHash.Bytes(), nil
}
