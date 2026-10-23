package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// handleAdminListAuditLogs serves GET /api/v1/admin/audit-logs.
//
// start_time and end_time are mandatory (api-design.md §1.7). That is the
// documented DoS guard: mvp_audit_logs is the largest table in the system and
// an unbounded scan of it is a self-inflicted outage. Both RFC 3339 and Unix
// seconds are accepted.
//
// The window is additionally capped at ADMIN_AUDIT_MAX_WINDOW. Requiring two
// bounds without capping their distance would be no guard at all — "1970 to
// now" satisfies the letter of it.
func (s *Server) handleAdminListAuditLogs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}

		startRaw := r.URL.Query().Get("start_time")
		endRaw := r.URL.Query().Get("end_time")
		if strings.TrimSpace(startRaw) == "" || strings.TrimSpace(endRaw) == "" {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		startTime, err := parseTimeParam(startRaw)
		if err != nil {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		endTime, err := parseTimeParam(endRaw)
		if err != nil {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if endTime.Before(startTime) {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if endTime.Sub(startTime) > s.cfg.Admin.AuditMaxWindow {
			s.writeAdminError(w, http.StatusBadRequest, "window_too_large")
			return
		}

		limit, _, err := s.parsePagination(r)
		if err != nil {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		// Keyset cursor. v1 took an offset, which made every page view re-scan and
		// re-count the whole matching range; the mandatory time bounds do not bound
		// that, because a DPO legitimately asks for a year.
		beforeSeq, err := parseInt64Param(r, "before_seq", 0)
		if err != nil || beforeSeq < 0 {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}

		var eventType *string
		if raw := strings.TrimSpace(r.URL.Query().Get("event_type")); raw != "" {
			if len(raw) > 100 || strings.IndexFunc(raw, func(c rune) bool {
				return (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_'
			}) >= 0 {
				s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
				return
			}
			eventType = &raw
		}

		start := pgtype.Timestamptz{Time: startTime, Valid: true}
		end := pgtype.Timestamptz{Time: endTime, Valid: true}

		page, err := s.adminStore(r).ListAuditLogsPage(r.Context(), db.ListAuditLogsPageParams{
			StartTime: start,
			EndTime:   end,
			EventType: eventType,
			BeforeSeq: beforeSeq,
			PageLimit: limit,
		})
		if err != nil {
			s.logger.Error("admin: list audit logs failed", "error", err.Error())
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		items := make([]adminAuditLogResponse, 0)
		if err := json.Unmarshal(page.Items, &items); err != nil {
			s.logger.Error("admin: decode audit page failed")
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		digest := sha256.Sum256(page.Items)
		payload := map[string]any{
			"start_time":   startTime.Format(time.RFC3339Nano),
			"end_time":     endTime.Format(time.RFC3339Nano),
			"result_count": len(items), "limit": limit, "before_seq": beforeSeq,
			"has_more": page.HasMore, "next_before_seq": page.NextBeforeSeq,
			"record_set_digest": hex.EncodeToString(digest[:]),
		}
		if eventType != nil {
			payload["event_type"] = *eventType
		}

		// Reading the tamper-evident log is itself an auditable act: without
		// this, the one surface that observes everything would observe nothing
		// about its own use. The payload records the window, not the results.
		adminaction.SetEvent(r.Context(), audit.Event{
			EventType:    audit.EventAdminAuditLogsQueried,
			ActionStatus: audit.StatusSuccess,
			ActorID:      actor,
			Payload:      payload,
		})

		s.writeAdminJSON(w, http.StatusOK, struct {
			Items []adminAuditLogResponse `json:"items"`
			Limit int32                   `json:"limit"`
			// HasMore and NextBeforeSeq replace the exact total: counting an
			// append-only table that grows without bound is not worth an O(n) scan
			// on every page view.
			HasMore       bool  `json:"has_more"`
			NextBeforeSeq int64 `json:"next_before_seq"`
		}{items, limit, page.HasMore, page.NextBeforeSeq})
	}
}

// chainVerifyParams holds the parsed cursor for a verification request.
type chainVerifyParams struct {
	afterSeq        int64
	throughSeq      int64
	hasThrough      bool
	predecessorHash []byte
	limit           int32
}

// parseChainVerifyParams requires continuations to retain the original upper
// watermark. A supplied predecessor digest is optional, not a trusted checkpoint.
func (s *Server) parseChainVerifyParams(r *http.Request) (chainVerifyParams, error) {
	afterSeq, err := parseInt64Param(r, "after_seq", 0)
	if err != nil {
		return chainVerifyParams{}, err
	}
	limit, err := parseInt64Param(r, "limit", int64(defaultChainVerifyLimit))
	if err != nil {
		return chainVerifyParams{}, err
	}
	if limit == 0 {
		limit = int64(defaultChainVerifyLimit)
	}
	if limit > int64(s.cfg.Admin.ChainVerifyMaxLimit) {
		limit = int64(s.cfg.Admin.ChainVerifyMaxLimit)
	}
	if limit <= 0 || limit > 5000 {
		return chainVerifyParams{}, errors.New("invalid verification limit")
	}
	through, err := parseInt64Param(r, "through_seq", 0)
	if err != nil {
		return chainVerifyParams{}, err
	}
	hasThrough := r.URL.Query().Has("through_seq")
	if (hasThrough && strings.TrimSpace(r.URL.Query().Get("through_seq")) == "") || (afterSeq > 0 && !hasThrough) || (hasThrough && afterSeq > through) {
		return chainVerifyParams{}, errors.New("invalid verification range")
	}
	var predecessor []byte
	if r.URL.Query().Has("predecessor_hash") {
		digest, err := audit.DecodeDigestHex(strings.ToLower(r.URL.Query().Get("predecessor_hash")))
		if err != nil {
			return chainVerifyParams{}, errors.New("invalid predecessor hash")
		}
		predecessor = digest.Bytes()
	}
	return chainVerifyParams{afterSeq: afterSeq, throughSeq: through, hasThrough: hasThrough, predecessorHash: predecessor, limit: int32(limit)}, nil
}

// defaultChainVerifyLimit is the page size when ?limit= is omitted.
const defaultChainVerifyLimit = 1000

// handleAdminVerifyAuditChain serves GET /api/v1/admin/audit-logs/verify.
//
// Both verification routes go through one walker (internal/audit/ledgerproof),
// which in turn uses internal/audit's single canonical serializer. v1 had a
// separate recomputation loop here for the audit chain and a different one in
// ledgerproof for the ledger; two implementations of the same check eventually
// disagree by a byte and report tampering across an intact chain.
func (s *Server) handleAdminVerifyAuditChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.runChainVerification(w, r, ledgerproof.ChainAudit, s.snapshotVerifier())
	}
}

// chainVerifier runs one verification pass. It is injected so a handler test can
// drive the HTTP contract — status codes, the recorded audit event, the response
// projection — against a constructed chain, without a database.
type chainVerifier func(context.Context, ledgerproof.Params) (ledgerproof.Result, error)

// snapshotVerifier is the production verifier: a bounded read-only snapshot.
func (s *Server) snapshotVerifier() chainVerifier {
	return func(ctx context.Context, p ledgerproof.Params) (ledgerproof.Result, error) {
		if s.deps.LedgerProofDB == nil {
			return ledgerproof.Result{}, errors.New("verification database unavailable")
		}
		return ledgerproof.VerifySnapshot(ctx, s.deps.LedgerProofDB, p)
	}
}

// handleAdminVerifyLedgerChain serves GET /api/v1/admin/ledger/verify.
func (s *Server) handleAdminVerifyLedgerChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.runChainVerification(w, r, ledgerproof.ChainLedger, s.snapshotVerifier())
	}
}

// chainVerifyScope describes exactly what a clean result does and does not prove.
// It is returned to the caller verbatim so an operator cannot mistake a
// database-relative check for independent historical authenticity: everything
// here is recomputed from the same database that would be rewritten by a
// privileged attacker. External anchoring is deliberately out of scope.
const (
	auditVerifyScope  = "stored_segment_relative_to_seed; not complete ingestion, tail-truncation detection, or independent historical authenticity"
	ledgerVerifyScope = "database_relative_chain_and_retained_payloads; erased payloads are authorized by erasure records, not recomputed; not complete ingestion or independent historical authenticity"
)

// Short, stable codes for the audit record. The prose above is for the operator
// reading the HTTP response; an audit payload needs a value that can be alerted
// on and correlated, and internal/adminaction enforces the enum.
const (
	auditVerifyScopeCode  = "audit_chain_database_relative"
	ledgerVerifyScopeCode = "ledger_chain_database_relative"
)

// runChainVerification verifies one chain and records the attempt.
//
// It stops at the first mismatch. Continuing would be misleading: every
// subsequent node chains off the broken one, so they would all "fail" and bury
// the single seq that actually matters under noise.
func (s *Server) runChainVerification(w http.ResponseWriter, r *http.Request, chain ledgerproof.Chain, verify chainVerifier) {
	actor, ok := s.adminActor(w, r)
	if !ok {
		return
	}
	p, err := s.parseChainVerifyParams(r)
	if err != nil {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	result, err := verify(r.Context(), ledgerproof.Params{
		Chain: chain, AfterSeq: p.afterSeq, ThroughSeq: p.throughSeq,
		HasThrough: p.hasThrough, PredecessorHash: p.predecessorHash, Limit: p.limit,
	})
	if err != nil {
		switch {
		case errors.Is(err, ledgerproof.ErrUnknownSeq):
			// The caller named a seq that does not exist. Approximating with a
			// neighbouring node would hand verification the wrong predecessor and
			// report a break in an intact chain.
			s.writeAdminError(w, http.StatusBadRequest, "unknown_seq")
		case errors.Is(err, ledgerproof.ErrMissingHead):
			s.writeAdminError(w, http.StatusBadRequest, "missing_head")
		default:
			s.logger.Error("admin: chain verification failed", "chain", string(chain))
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
		}
		return
	}

	scope, scopeCode := auditVerifyScope, auditVerifyScopeCode
	if chain == ledgerproof.ChainLedger {
		scope, scopeCode = ledgerVerifyScope, ledgerVerifyScopeCode
	}
	base := adminChainVerifyResponse{
		FailureReason: result.FailureReason, Chain: result.Chain,
		AfterSeq: result.AfterSeq, ThroughSeq: result.ThroughSeq,
		SeedHash: result.SeedHash, SeedSource: result.SeedSource, Scope: scope,
		LastHash: result.LastHash, Complete: result.Complete, Verified: result.Verified,
		Checked: result.Checked, FirstSeq: result.FirstSeq, LastSeq: result.LastSeq,
		BrokenAtSeq: result.BrokenAtSeq, ExpectedHash: result.ExpectedHash,
		StoredHash: result.StoredHash, NextAfterSeq: result.NextAfterSeq,
	}

	payload := map[string]any{
		"chain": result.Chain, "verified": result.Verified, "checked": result.Checked,
		"after_seq": result.AfterSeq, "through_seq": result.ThroughSeq,
		"complete": result.Complete, "verification_scope": scopeCode,
		"erased_checked": result.ErasedChecked,
	}
	if result.SeedHash != "" {
		payload["seed_hash"], payload["seed_source"] = result.SeedHash, result.SeedSource
	}
	if result.BrokenAtSeq != nil {
		payload["broken_at_seq"] = *result.BrokenAtSeq
	}
	if result.LastHash != "" {
		payload["last_hash"] = result.LastHash
	}
	status := audit.StatusSuccess
	if result.FailureReason != nil {
		payload["failure_reason"] = *result.FailureReason
		// An empty range is not a tamper alarm; every other failure is. v1 also
		// excused "no_retained_records", which existed because erasure could empty
		// a span. That excuse is gone: in v2 an absent payload is either covered by
		// an erasure record or it is tampering, and the walker already decided
		// which.
		if *result.FailureReason != "no_stored_records" {
			status = audit.StatusFailure
		}
	}

	// Reading the tamper-evident log is itself an auditable act: without this, the
	// one surface that observes everything would observe nothing about its own use.
	adminaction.SetEvent(r.Context(), audit.Event{EventType: audit.EventAdminChainVerified,
		ActionStatus: status, ActorID: actor, Payload: payload})

	// adminTransaction withholds this content-free response until audit commits.
	if chain == ledgerproof.ChainLedger {
		s.writeAdminJSON(w, http.StatusOK, adminLedgerVerifyResponse{
			adminChainVerifyResponse: base, ErasedChecked: result.ErasedChecked,
		})
		return
	}
	s.writeAdminJSON(w, http.StatusOK, base)
}
