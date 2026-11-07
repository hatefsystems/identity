// Package receiptreconcile provides bounded operational receipt assurance,
// separate from structural ledger verification and never used by signer reseeding.
package receiptreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

var (
	// ErrOptions reports invalid operation/proof ceilings.
	ErrOptions = errors.New("ledger receipts: invalid bounded options")
	// ErrDatabase deliberately omits database error values and receipt material.
	ErrDatabase = errors.New("ledger receipts: snapshot unavailable")
)

// Options limits total operations and Class C nodes, not just individual pages.
type Options struct {
	Limit      int
	ProofLimit int
}

// Summary contains no identifiers, receipt bodies or proof digests. Counts apply
// only to the inspected inventory; a capped run is not full-inventory assurance.
type Summary struct {
	Inspected          int  `json:"inspected"`
	RecordedPending    int  `json:"recorded_pending"`
	Chained            int  `json:"chained"`
	LegacyUnbound      int  `json:"legacy_unbound"`
	MissingUnavailable int  `json:"missing_unavailable"`
	Invalid            int  `json:"invalid"`
	Incomplete         int  `json:"incomplete"`
	Pages              int  `json:"pages"`
	InventoryCapped    bool `json:"inventory_capped"`
	InventoryComplete  bool `json:"inventory_complete"`
	ProofChecked       int  `json:"proof_checked"`
	ProofComplete      bool `json:"proof_complete"`
	ProofVerified      bool `json:"proof_verified"`
	// No aggregate "pass": even complete database-relative evidence does not
	// prove that a compromised trusted purge credential honored policy.
}

// ReconcileSnapshot uses one READ ONLY REPEATABLE READ snapshot, keyset-paged
// inventory, bounded span queries and a bounded genesis-relative Class C linkage
// proof. Receipt leaves are checked separately; unrelated narrative bodies are
// never read, so large historical payloads cannot exhaust snapshot memory.
// The caller must probe its separately scoped credentials before invoking it.
func ReconcileSnapshot(ctx context.Context, pool ledgerproof.Beginner, opts Options) (Summary, error) {
	if pool == nil || opts.Limit < 1 || opts.Limit > 1000 || opts.ProofLimit < 1 || opts.ProofLimit > 10000 {
		return Summary{}, ErrOptions
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Summary{}, ErrDatabase
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer done()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='20s'"); err != nil {
		return Summary{}, ErrDatabase
	}
	proof, proofErr := verifyLinks(ctx, tx, opts.ProofLimit)
	if proofErr != nil && !errors.Is(proofErr, ledgerproof.ErrMissingHead) {
		return Summary{}, ErrDatabase
	}
	summary := Summary{ProofChecked: proof.Checked, ProofComplete: proof.Complete, ProofVerified: proof.Verified && proofErr == nil}
	queries := db.New(tx)
	after := uuid.Nil
	for {
		// One extra operation detects a capped inventory without certifying it.
		pageSize := min(100, opts.Limit-summary.Inspected+1)
		if pageSize < 1 || pageSize > 100 {
			return Summary{}, ErrOptions
		}
		ids, err := queries.ListLedgerReceiptOperations(ctx, db.ListLedgerReceiptOperationsParams{AfterID: after, PageLimit: int32(pageSize)})
		if err != nil {
			return Summary{}, ErrDatabase
		}
		summary.Pages++
		for _, id := range ids {
			if summary.Inspected == opts.Limit {
				summary.InventoryCapped = true
				return summary, nil
			}
			evidence, err := readEvidence(ctx, queries, id)
			if err != nil {
				return Summary{}, err
			}
			summary.Inspected++
			switch classify(evidence, proof, proofErr != nil) {
			case recordedPending:
				summary.RecordedPending++
			case chained:
				summary.Chained++
			case legacyUnbound:
				summary.LegacyUnbound++
			case missingUnavailable:
				summary.MissingUnavailable++
			case invalid:
				summary.Invalid++
			case incomplete:
				summary.Incomplete++
			}
			after = id
		}
		if len(ids) < pageSize {
			summary.InventoryComplete = true
			return summary, nil
		}
	}
}

func verifyLinks(ctx context.Context, tx db.DBTX, limit int) (ledgerproof.Result, error) {
	source := ledgerproof.NewSource(tx, ledgerproof.ChainAudit)
	head, err := source.Head(ctx)
	if err != nil {
		return ledgerproof.Result{}, err
	}
	storedHead, err := audit.DecodeDigest(head.Hash)
	if err != nil {
		return ledgerproof.Result{}, ledgerproof.ErrMissingHead
	}
	result := ledgerproof.Result{Verified: true, ThroughSeq: head.MaxSeq}
	expectedHead := audit.Genesis()
	if head.MaxSeq > 0 {
		raw, err := source.HashAt(ctx, head.MaxSeq)
		if err != nil {
			return ledgerproof.Result{}, err
		}
		expectedHead, err = audit.DecodeDigest(raw)
		if err != nil {
			result.Verified = false
			return result, nil
		}
	}
	if head.Invalid || head.Seq < 0 || head.MaxSeq < 0 || head.Seq != head.MaxSeq || storedHead != expectedHead {
		result.Verified = false
		return result, nil
	}
	q := db.New(tx)
	previous := audit.Genesis()
	var after int64
	for after < head.MaxSeq && result.Checked < limit {
		pageSize := min(100, limit-result.Checked)
		if pageSize < 1 || pageSize > 100 {
			return ledgerproof.Result{}, ErrOptions
		}
		rows, err := q.ListLedgerReceiptProofNodes(ctx, db.ListLedgerReceiptProofNodesParams{AfterSeq: after, ThroughSeq: head.MaxSeq, PageLimit: int32(pageSize)})
		if err != nil {
			return ledgerproof.Result{}, err
		}
		if len(rows) == 0 {
			result.Verified = false
			return result, nil
		}
		for _, row := range rows {
			leaf, leafErr := audit.DecodeDigest(row.LeafHash)
			chain, chainErr := audit.DecodeDigest(row.ChainHash)
			if leafErr != nil || chainErr != nil || row.Seq <= after || audit.ChainAudit(previous, leaf) != chain {
				result.Verified = false
				return result, nil
			}
			result.Checked++
			after, previous = row.Seq, chain
		}
	}
	if after > 0 {
		result.LastSeq = &after
	}
	result.Complete = after == head.MaxSeq
	return result, nil
}

type evidence struct {
	id          uuid.UUID
	spans       [][2]int64
	erasedAt    []time.Time
	spansCapped bool
	outbox      *audit.Envelope
	badOutbox   bool
	badRecord   bool
	chainSeq    int64
	record      *audit.AuditRecord
	leaf        []byte
}

func readEvidence(ctx context.Context, q *db.Queries, id uuid.UUID) (evidence, error) {
	e := evidence{id: id}
	spans, err := q.ListLedgerReceiptSpans(ctx, id)
	if err != nil {
		return e, ErrDatabase
	}
	if len(spans) > 5000 {
		e.spansCapped = true
		return e, nil
	}
	for _, span := range spans {
		e.spans = append(e.spans, [2]int64{span.FirstSeq, span.LastSeq})
		e.erasedAt = append(e.erasedAt, span.ErasedAt.Time)
	}
	outbox, err := q.GetLedgerReceiptOutbox(ctx, id)
	if err == nil {
		var envelope audit.Envelope
		e.badOutbox = !outbox.AdminAction || len(outbox.Envelope) > 8192 || json.Unmarshal([]byte(outbox.Envelope), &envelope) != nil
		if !e.badOutbox {
			e.outbox = &envelope
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return e, ErrDatabase
	}
	row, err := q.GetLedgerChainedReceipt(ctx, id)
	if err == nil {
		e.chainSeq, e.leaf = row.Seq, row.LeafHash
		e.badRecord = row.PayloadPresent && !row.BodyBounded
		if row.PayloadPresent && row.ActorID.Valid && row.ActorSpiffeID != nil && row.EventType != nil &&
			row.ActionStatus != nil && row.ClientIp != nil && row.Timestamp.Valid {
			e.record = &audit.AuditRecord{ID: row.EventID.String(), ActorID: row.ActorID.UUID.String(),
				ActorSPIFFEID: *row.ActorSpiffeID, EventType: *row.EventType, ActionStatus: *row.ActionStatus,
				ClientIP: *row.ClientIp, UserAgent: row.UserAgent, Payload: row.Payload, Timestamp: row.Timestamp.Time}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return e, ErrDatabase
	}
	return e, nil
}

type state uint8

const (
	recordedPending state = iota
	chained
	legacyUnbound
	missingUnavailable
	invalid
	incomplete
)

type receipt struct {
	OperationID     string  `json:"operation_id"`
	Cutoff          string  `json:"cutoff"`
	Deleted         int64   `json:"deleted_count"`
	Held            int64   `json:"held_count"`
	DryRun          bool    `json:"dry_run"`
	Outcome         string  `json:"outcome"`
	Highwater       int64   `json:"highwater_seq"`
	ManifestVersion *int    `json:"span_manifest_version"`
	ManifestHash    *string `json:"span_manifest_sha256"`
}

func classify(e evidence, proof ledgerproof.Result, proofUnavailable bool) state {
	if e.spansCapped {
		return incomplete
	}
	if e.badOutbox || e.badRecord {
		return invalid
	}
	if e.outbox == nil && e.record == nil {
		return missingUnavailable
	}
	var rec audit.AuditRecord
	if e.outbox != nil {
		if e.outbox.EventID != e.id || e.outbox.SchemaVersion != audit.EnvelopeSchemaVersion ||
			e.outbox.SubjectID != "" || e.outbox.Security != nil {
			return invalid
		}
		rec = e.outbox.AuditRecord()
	}
	if e.record != nil {
		storedRecord := *e.record
		// PostgreSQL and JSON decoding may use different timezone locations for
		// the same instant. Compare the canonical clock, not time.Time internals.
		storedRecord.Timestamp = audit.NormalizeChainTime(storedRecord.Timestamp)
		rec.Timestamp = audit.NormalizeChainTime(rec.Timestamp)
		if e.outbox != nil && rec != storedRecord {
			return invalid
		}
		rec = storedRecord
		leaf, err := audit.LeafAudit(rec)
		stored, decodeErr := audit.DecodeDigest(e.leaf)
		if err != nil || decodeErr != nil || leaf != stored {
			return invalid
		}
	}
	if rec.ID != e.id.String() || rec.ActorID != uuid.Nil.String() || rec.ActorSPIFFEID != audit.LedgerRetentionActorSPIFFEID ||
		rec.ActionStatus != audit.StatusSuccess || rec.ClientIP != "" || rec.UserAgent != "" {
		return invalid
	}
	content, ok := decodeReceipt(rec.Payload)
	if !ok || content.OperationID != e.id.String() || content.DryRun || content.Deleted < 0 || content.Deleted > 5000 ||
		content.Held < 0 || content.Held > 5000 || content.Highwater < 0 {
		return invalid
	}
	cutoff, err := time.Parse(time.RFC3339Nano, content.Cutoff)
	if err != nil || audit.FormatChainTime(cutoff) != content.Cutoff || !rec.Timestamp.Equal(cutoff) {
		return invalid
	}
	if content.Deleted > 0 {
		if content.Outcome != "purged" || rec.EventType != audit.EventLegalLedgerPurged {
			return invalid
		}
		if len(e.spans) == 0 {
			return missingUnavailable
		}
	} else if content.Held == 0 || content.Outcome != "held" || rec.EventType != audit.EventLegalLedgerPurgeSkipped {
		return invalid
	}
	for _, erasedAt := range e.erasedAt {
		if !erasedAt.Equal(cutoff) {
			return invalid
		}
	}
	manifest, err := ledgerproof.SpanManifest(e.spans, content.Deleted, content.Highwater)
	if err != nil {
		return invalid
	}
	if content.ManifestVersion == nil && content.ManifestHash == nil {
		return legacyUnbound
	}
	if content.ManifestVersion == nil || *content.ManifestVersion != 1 || content.ManifestHash == nil || *content.ManifestHash != manifest {
		return invalid
	}
	if e.chainSeq == 0 {
		return recordedPending
	}
	if e.record == nil {
		return missingUnavailable
	}
	if proofUnavailable {
		return incomplete
	}
	if !proof.Verified {
		return invalid
	}
	if proof.LastSeq == nil || e.chainSeq > *proof.LastSeq {
		return incomplete
	}
	// A successfully verified prefix covers this receipt, but does not claim a
	// full-chain pass. Summary.ProofComplete remains false for a partial proof.
	return chained
}

// decodeReceipt rejects duplicates, aliases, unknown fields and null required
// fields. Legacy means both manifest fields are absent, never malformed/present.
func decodeReceipt(payload string) (receipt, bool) {
	if len(payload) > 4096 {
		return receipt{}, false
	}
	dec := json.NewDecoder(strings.NewReader(payload))
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') {
		return receipt{}, false
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return receipt{}, false
		}
		key, ok := token.(string)
		if !ok {
			return receipt{}, false
		}
		if _, duplicate := fields[key]; duplicate {
			return receipt{}, false
		}
		switch key {
		case "operation_id", "cutoff", "deleted_count", "held_count", "dry_run", "outcome", "highwater_seq", "span_manifest_version", "span_manifest_sha256":
		default:
			return receipt{}, false
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil || string(value) == "null" {
			return receipt{}, false
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return receipt{}, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return receipt{}, false
	}
	for _, key := range []string{"operation_id", "cutoff", "deleted_count", "held_count", "dry_run", "outcome", "highwater_seq"} {
		if _, exists := fields[key]; !exists {
			return receipt{}, false
		}
	}
	var result receipt
	if json.Unmarshal([]byte(payload), &result) != nil {
		return receipt{}, false
	}
	return result, true
}
