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

		limit, offset, err := s.parsePagination(r)
		if err != nil {
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
			StartTime:  start,
			EndTime:    end,
			EventType:  eventType,
			PageOffset: offset,
			PageLimit:  limit,
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
			"result_count": len(items), "limit": limit, "offset": offset,
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

		s.writeAdminJSON(w, http.StatusOK, adminPage[adminAuditLogResponse]{
			Items: items, Total: page.Total, Limit: limit, Offset: offset,
		})
	}
}

// chainVerifyParams holds the parsed cursor for a verification request.
type chainVerifyParams struct {
	afterSeq        int64
	throughSeq      int64
	hasThrough      bool
	predecessorHash string
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
	predecessor := r.URL.Query().Get("predecessor_hash")
	if r.URL.Query().Has("predecessor_hash") {
		if _, err := audit.DecodeChainHash(predecessor); err != nil {
			return chainVerifyParams{}, errors.New("invalid predecessor hash")
		}
		predecessor = strings.ToLower(predecessor)
	}
	return chainVerifyParams{afterSeq: afterSeq, throughSeq: through, hasThrough: hasThrough, predecessorHash: predecessor, limit: int32(limit)}, nil
}

// defaultChainVerifyLimit is the page size when ?limit= is omitted.
const defaultChainVerifyLimit = 1000

// handleAdminVerifyAuditChain serves GET /api/v1/admin/audit-logs/verify.
//
// It recomputes chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record))
// over a page of mvp_audit_logs using audit.SerializeAudit and audit.ChainHash
// — never a local reimplementation. A second serializer would eventually
// disagree with the signer's by a byte and report tampering across an intact
// chain, which is why internal/audit/chain.go owns exactly one.
func (s *Server) handleAdminVerifyAuditChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.runChainVerification(w, r, "audit", func(ctx context.Context, p chainVerifyParams) ([]chainRow, error) {
			logs, err := s.adminStore(r).ListAuditLogsForChainVerification(ctx, db.ListAuditLogsForChainVerificationParams{
				AfterSeq:   p.afterSeq,
				ThroughSeq: p.throughSeq,
				PageLimit:  p.limit + 1,
			})
			if err != nil {
				return nil, err
			}
			rows := make([]chainRow, 0, len(logs))
			for _, l := range logs {
				rows = append(rows, chainRow{
					seq:        l.Seq,
					storedHash: l.ChainHash,
					body: audit.SerializeAudit(audit.AuditRecord{
						ID:            l.ID.String(),
						ActorID:       l.ActorID.String(),
						ActorSPIFFEID: l.ActorSpiffeID,
						EventType:     l.EventType,
						ActionStatus:  l.ActionStatus,
						ClientIP:      l.ClientIp,
						UserAgent:     l.UserAgent,
						Payload:       l.Payload,
						Timestamp:     l.Timestamp.Time,
					}),
				})
			}
			return rows, nil
		}, s.adminStore(r).GetAuditLogChainHashBySeq, s.adminStore(r).GetAuditLogHighWaterSeq)
	}
}

// handleAdminVerifyLedgerChain serves GET /api/v1/admin/ledger/verify.
func (s *Server) handleAdminVerifyLedgerChain() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.runChainVerification(w, r, "ledger", func(ctx context.Context, p chainVerifyParams) ([]chainRow, error) {
			events, err := s.adminStore(r).ListSecurityEventsForChainVerification(ctx, db.ListSecurityEventsForChainVerificationParams{
				AfterSeq:   p.afterSeq,
				ThroughSeq: p.throughSeq,
				PageLimit:  p.limit + 1,
			})
			if err != nil {
				return nil, err
			}
			rows := make([]chainRow, 0, len(events))
			for _, e := range events {
				rows = append(rows, chainRow{
					seq:        e.Seq,
					storedHash: e.ChainHash,
					body: audit.SerializeLedger(audit.LedgerRecord{
						ID:                 e.ID.String(),
						AccountRef:         e.AccountRef.String(),
						IdentityBlindIndex: e.IdentityBlindIndex,
						EventType:          e.EventType,
						ClientIP:           e.ClientIp,
						IPSubnet:           e.IpSubnet,
						UserAgent:          e.UserAgent,
						DeviceFingerprint:  e.DeviceFingerprint,
						ClientID:           e.ClientID,
						Scope:              e.Scope,
						Timestamp:          e.Timestamp.Time,
						RetainUntil:        e.RetainUntil.Time,
					}),
				})
			}
			return rows, nil
		}, s.adminStore(r).GetSecurityEventChainHashBySeq, s.adminStore(r).GetSecurityEventHighWaterSeq)
	}
}

// chainRow is one row reduced to what verification needs.
type chainRow struct {
	seq        int64
	storedHash string
	body       []byte
}

// chainFetcher loads a page of rows for verification.
type chainFetcher func(ctx context.Context, p chainVerifyParams) ([]chainRow, error)

// chainSeeder returns the stored digest at an exact seq.
type chainSeeder func(ctx context.Context, seq int64) (string, error)

// runChainVerification is the shared engine behind both verify endpoints.
//
// It stops at the first mismatch. Continuing would be misleading: every
// subsequent row chains off the broken one, so they would all "fail" and bury
// the single seq that actually matters under noise.
func (s *Server) runChainVerification(
	w http.ResponseWriter,
	r *http.Request,
	chainName string,
	fetch chainFetcher,
	seed chainSeeder,
	highWater func(context.Context) (int64, error),
) {
	actor, ok := s.adminActor(w, r)
	if !ok {
		return
	}

	params, err := s.parseChainVerifyParams(r)
	if err != nil {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !params.hasThrough {
		params.throughSeq, err = highWater(r.Context())
		if err != nil {
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	// An explicit upper boundary must still exist. Never claim a completed proof
	// when a requested tail has disappeared between pages.
	if params.throughSeq > 0 {
		if _, err := seed(r.Context(), params.throughSeq); err != nil {
			if isNoRows(err) {
				s.writeAdminError(w, http.StatusBadRequest, "unknown_through_seq")
			} else {
				s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			}
			return
		}
	}

	// Seed the predecessor digest. after_seq == 0 starts at genesis, which is
	// chained like any other record so there is no special case to forge a new
	// "first" row against.
	prev := audit.GenesisChainHash
	seedSource := "genesis"
	if params.afterSeq > 0 {
		stored, seedErr := seed(r.Context(), params.afterSeq)
		if seedErr != nil {
			if isNoRows(seedErr) {
				// The caller named a seq that does not exist. Approximating
				// with a neighbouring row would hand verification the wrong
				// predecessor and report a break in an intact chain.
				s.writeAdminError(w, http.StatusBadRequest, "unknown_after_seq")
				return
			}
			s.logger.Error("admin: chain verify seed failed", "chain", chainName, "error", seedErr.Error())
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		decoded, decodeErr := audit.DecodeChainHash(stored)
		if decodeErr != nil {
			s.logger.Error("admin: stored chain hash is malformed",
				"chain", chainName, "seq", params.afterSeq, "error", decodeErr.Error())
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		prev = decoded
		seedSource = "database_predecessor"
	}
	storedSeed := hex.EncodeToString(prev[:])
	seedMismatch := false
	if params.predecessorHash != "" {
		seedMismatch = params.predecessorHash != storedSeed
		prev, _ = audit.DecodeChainHash(params.predecessorHash)
		seedSource = "supplied_predecessor"
	}
	seedHash := hex.EncodeToString(prev[:])

	rows, err := fetch(r.Context(), params)
	if err != nil {
		s.logger.Error("admin: chain verify fetch failed", "chain", chainName, "error", err.Error())
		s.writeAdminError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := adminChainVerifyResponse{
		Verified: true, Chain: chainName, AfterSeq: params.afterSeq, ThroughSeq: params.throughSeq,
		SeedHash: seedHash, SeedSource: seedSource,
		Scope: "stored_segment_relative_to_seed; not complete ingestion, tail-truncation detection, or independent historical authenticity",
	}
	hasMore := len(rows) > int(params.limit)
	if hasMore {
		rows = rows[:params.limit]
	}
	if seedMismatch {
		resp.Verified = false
		resp.FailureReason = stringPtr("predecessor_mismatch")
		resp.BrokenAtSeq = int64Ptr(params.afterSeq)
		resp.ExpectedHash, resp.StoredHash = stringPtr(seedHash), stringPtr(storedSeed)
		rows = nil
	} else if len(rows) == 0 {
		resp.Verified = false
		resp.FailureReason = stringPtr("no_stored_records")
	}
	lastSeq := params.afterSeq
	for i, row := range rows {
		if row.seq <= lastSeq || row.seq > params.throughSeq {
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		lastSeq = row.seq
		expected := audit.ChainHash(prev, row.body)
		if i == 0 {
			resp.FirstSeq = int64Ptr(row.seq)
		}
		resp.Checked++
		resp.LastSeq = int64Ptr(row.seq)

		if expected != row.storedHash {
			resp.Verified = false
			resp.BrokenAtSeq = int64Ptr(row.seq)
			resp.ExpectedHash = stringPtr(expected)
			resp.StoredHash = stringPtr(row.storedHash)
			resp.FailureReason = stringPtr("hash_mismatch")
			break
		}

		decoded, decodeErr := audit.DecodeChainHash(row.storedHash)
		if decodeErr != nil {
			// Unreachable while expected == storedHash (expected is always
			// well-formed hex), but a malformed column must never silently
			// propagate into the next digest.
			s.logger.Error("admin: stored chain hash is malformed mid-scan",
				"chain", chainName, "seq", row.seq, "error", decodeErr.Error())
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		prev = decoded
		resp.LastHash = stringPtr(row.storedHash)
	}

	// A full final page is final too: only a real lookahead row implies another
	// page. Complete refers exclusively to this stored segment and watermark.
	if resp.Verified && hasMore && resp.LastSeq != nil {
		resp.NextAfterSeq = resp.LastSeq
	} else if resp.Verified && resp.LastSeq != nil {
		if *resp.LastSeq == params.throughSeq {
			resp.Complete = true
		} else {
			resp.Verified = false
			resp.FailureReason = stringPtr("missing_upper_boundary")
		}
	}

	// A detected break is the highest-severity signal this system produces, so
	// it goes into the tamper-evident log itself and not only into an HTTP
	// response the caller is free to discard.
	payload := map[string]any{
		"chain":              chainName,
		"verified":           resp.Verified,
		"checked":            resp.Checked,
		"after_seq":          params.afterSeq,
		"through_seq":        params.throughSeq,
		"seed_hash":          seedHash,
		"seed_source":        seedSource,
		"verification_scope": "stored_segment_relative_to_seed",
		"complete":           resp.Complete,
	}
	if resp.BrokenAtSeq != nil {
		payload["broken_at_seq"] = *resp.BrokenAtSeq
	}
	if resp.FailureReason != nil {
		payload["failure_reason"] = *resp.FailureReason
	}
	if resp.LastHash != nil {
		payload["last_hash"] = *resp.LastHash
	}
	status := audit.StatusSuccess
	if !resp.Verified {
		status = audit.StatusFailure
	}
	adminaction.SetEvent(r.Context(), audit.Event{
		EventType:    audit.EventAdminChainVerified,
		ActionStatus: status,
		ActorID:      actor,
		Payload:      payload,
	})

	s.writeAdminJSON(w, http.StatusOK, resp)
}
