package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func verificationRows(sequences ...int64) []chainRow {
	var rows []chainRow
	prev := audit.GenesisChainHash
	for _, seq := range sequences {
		body := audit.SerializeAudit(audit.AuditRecord{ID: uuid.NewString(), ActorID: uuid.NewString(), Payload: fmt.Sprintf(`{"private":"private-value-%d"}`, seq), ClientIP: "192.0.2.254", UserAgent: "private-agent", Timestamp: time.Unix(seq, 0)})
		hash := audit.ChainHash(prev, body)
		rows = append(rows, chainRow{seq: seq, storedHash: hash, body: body})
		prev, _ = audit.DecodeChainHash(hash)
	}
	return rows
}

func verifyPage(t *testing.T, rows []chainRow, query string, mutateFetch func([]chainRow) []chainRow) (*httptest.ResponseRecorder, adminChainVerifyResponse, *adminaction.Operation) {
	t.Helper()
	s := &Server{cfg: config.Config{Admin: config.AdminConfig{ChainVerifyMaxLimit: 5000}}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	op := &adminaction.Operation{ID: uuid.New()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs/verify"+query, nil)
	r = r.WithContext(adminaction.WithContext(rbac.WithActor(r.Context(), uuid.New()), op))
	w := httptest.NewRecorder()
	fetch := func(_ context.Context, p chainVerifyParams) ([]chainRow, error) {
		var page []chainRow
		for _, row := range rows {
			if row.seq > p.afterSeq && row.seq <= p.throughSeq {
				page = append(page, row)
				if len(page) == int(p.limit)+1 {
					break
				}
			}
		}
		if mutateFetch != nil {
			page = mutateFetch(page)
		}
		return page, nil
	}
	seed := func(_ context.Context, seq int64) (string, error) {
		for _, row := range rows {
			if row.seq == seq {
				return row.storedHash, nil
			}
		}
		return "", pgx.ErrNoRows
	}
	highWater := func(context.Context) (int64, error) {
		if len(rows) == 0 {
			return 0, nil
		}
		return rows[len(rows)-1].seq, nil
	}
	s.runChainVerification(w, r, "audit", fetch, seed, highWater)
	var response adminChainVerifyResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
	}
	return w, response, op
}

func TestAdminVerificationFixedWatermarkAndTrueLookahead(t *testing.T) {
	rows := verificationRows(2, 8, 11, 18) // Allocation holes do not break hash links.
	w, first, op := verifyPage(t, rows, "?limit=2", nil)
	if w.Code != http.StatusOK || !first.Verified || first.Complete || first.ThroughSeq != 18 || first.NextAfterSeq == nil || *first.NextAfterSeq != 8 || first.Checked != 2 {
		t.Fatalf("first page: %s", w.Body.String())
	}
	if first.SeedSource != "genesis" || first.LastHash == nil || *first.LastHash != rows[1].storedHash {
		t.Fatal("missing actual seed/continuation digest")
	}
	if op.Event.EventType != audit.EventAdminChainVerified || op.Event.Security != nil || op.Event.Payload["through_seq"] != int64(18) {
		t.Fatal("verification did not record bounded Class C event")
	}
	// A new row (including verification's own audit event) is outside the fixed head.
	prev, _ := audit.DecodeChainHash(rows[3].storedHash)
	body := []byte("new private record")
	rows = append(rows, chainRow{seq: 21, body: body, storedHash: audit.ChainHash(prev, body)})
	w, last, _ := verifyPage(t, rows, "?limit=2&after_seq=8&through_seq=18&predecessor_hash="+*first.LastHash, nil)
	if w.Code != http.StatusOK || !last.Verified || !last.Complete || last.NextAfterSeq != nil || last.Checked != 2 || last.LastSeq == nil || *last.LastSeq != 18 {
		t.Fatalf("full final page: %s", w.Body.String())
	}
	if last.SeedSource != "supplied_predecessor" || last.SeedHash != *first.LastHash {
		t.Fatal("incorrect reported seed")
	}
	for _, forbidden := range []string{"private-value", "192.0.2.254", "private-agent", "actor_id", "payload", "identity_blind_index", "account_ref"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("verification leaks %s", forbidden)
		}
	}
	if !strings.Contains(last.Scope, "not complete ingestion") {
		t.Fatal("verification scope overclaims evidence")
	}
}

func TestAdminVerificationMissingHistoryNeverProvesSegment(t *testing.T) {
	rows := verificationRows(1, 3, 8)
	tests := []struct {
		name, query string
		rows        []chainRow
		code        int
		reason      string
	}{
		{"empty", "", nil, 200, "no_stored_records"},
		{"missing predecessor", "?after_seq=2&through_seq=8", rows, 400, ""},
		{"missing upper boundary", "?through_seq=9", rows, 400, ""},
		{"moving resume rejected", "?after_seq=1", rows, 400, ""},
		{"empty segment", "?after_seq=8&through_seq=8", rows, 200, "no_stored_records"},
		{"purged prefix", "", rows[1:], 200, "hash_mismatch"},
		{"purged interior", "", []chainRow{rows[0], rows[2]}, 200, "hash_mismatch"},
		{"wrong prior digest", "?after_seq=1&through_seq=8&predecessor_hash=" + strings.Repeat("a", 64), rows, 200, "predecessor_mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, response, _ := verifyPage(t, tt.rows, tt.query, nil)
			if w.Code != tt.code || response.Verified || response.Complete || response.NextAfterSeq != nil {
				t.Fatalf("false proof: %d %s", w.Code, w.Body.String())
			}
			if tt.reason != "" && (response.FailureReason == nil || *response.FailureReason != tt.reason) {
				t.Fatalf("failure reason: %s", w.Body.String())
			}
		})
	}
}

func TestAdminVerificationReportsLegacyPrecisionDefectWithoutRepair(t *testing.T) {
	record := audit.AuditRecord{ID: uuid.NewString(), ActorID: uuid.NewString(), Timestamp: time.Unix(1789695500, 123456789), Payload: "{}"}
	oldHash := audit.ChainHash(audit.GenesisChainHash, audit.SerializeAudit(record))
	record.Timestamp = record.Timestamp.Truncate(time.Microsecond)
	rows := []chainRow{{seq: 4, storedHash: oldHash, body: audit.SerializeAudit(record)}}
	w, result, _ := verifyPage(t, rows, "", nil)
	if w.Code != 200 || result.Verified || result.Checked != 1 || result.BrokenAtSeq == nil || *result.BrokenAtSeq != 4 {
		t.Fatalf("precision defect hidden: %s", w.Body.String())
	}
	if rows[0].storedHash != oldHash {
		t.Fatal("historical hash rewritten")
	}
}

func TestAdminVerificationDetectsUpperBoundaryLostDuringScan(t *testing.T) {
	w, response, _ := verifyPage(t, verificationRows(1, 2), "", func(rows []chainRow) []chainRow { return rows[:1] })
	if response.Verified || response.FailureReason == nil || *response.FailureReason != "missing_upper_boundary" {
		t.Fatalf("lost tail falsely verified: %s", w.Body.String())
	}
}

func TestAdminVerificationRejectsMalformedBounds(t *testing.T) {
	for _, query := range []string{"?limit=-1", "?after_seq=-1", "?through_seq=-1", "?after_seq=3&through_seq=2", "?through_seq=", "?predecessor_hash=", "?predecessor_hash=abc", "?after_seq=9223372036854775808"} {
		w, _, _ := verifyPage(t, verificationRows(1, 2), query, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("accepted %s: %d", query, w.Code)
		}
	}
}

type ledgerHTTPSource struct {
	head  ledgerproof.Head
	steps []ledgerproof.Step
}

func (s ledgerHTTPSource) Head(context.Context) (ledgerproof.Head, error) { return s.head, nil }
func (s ledgerHTTPSource) Boundary(_ context.Context, seq int64) ([]ledgerproof.Step, error) {
	var out []ledgerproof.Step
	for _, step := range s.steps {
		if step.FirstSeq <= seq && step.LastSeq >= seq || step.Record == nil && step.PredecessorSeq == seq {
			out = append(out, step)
		}
	}
	return out, nil
}
func (s ledgerHTTPSource) Page(_ context.Context, after, through int64, limit int32) ([]ledgerproof.Step, error) {
	var out []ledgerproof.Step
	for _, step := range s.steps {
		if step.LastSeq > after && step.FirstSeq <= through {
			out = append(out, step)
			if len(out) == int(limit) {
				break
			}
		}
	}
	return out, nil
}

func TestAdminLedgerRetentionResponseAndAudit(t *testing.T) {
	record := audit.LedgerRecord{ID: uuid.NewString(), AccountRef: uuid.NewString(), EventType: "private-event", ClientIP: stringPtr("192.0.2.123"), Timestamp: time.Now().Truncate(time.Microsecond)}
	hash := audit.ChainHash(audit.GenesisChainHash, audit.SerializeLedger(record))
	live := ledgerproof.Step{Checkpoint: ledgerproof.Checkpoint{FirstSeq: 4, LastSeq: 4, TerminalHash: hash}, Record: &record}
	erased := ledgerproof.Step{Checkpoint: ledgerproof.Checkpoint{FirstSeq: 1, LastSeq: 4, PredecessorHash: strings.Repeat("0", 64), TerminalHash: hash, ErasedCount: 2}}
	for _, tc := range []struct {
		name, query, reason, status string
		step                        ledgerproof.Step
		verified, restart           bool
	}{
		{"live", "", "", audit.StatusSuccess, live, true, false},
		{"all purged", "", "no_retained_records", audit.StatusSuccess, erased, false, false},
		{"compacted cursor", "?after_seq=1&through_seq=4", "retention_boundary_unavailable", audit.StatusSuccess, erased, false, true},
		{"supplied mismatch", "?after_seq=4&through_seq=4&predecessor_hash=" + strings.Repeat("a", 64), "predecessor_mismatch", audit.StatusFailure, erased, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: config.Config{Admin: config.AdminConfig{ChainVerifyMaxLimit: 5000}}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			op := &adminaction.Operation{ID: uuid.New()}
			r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ledger/verify"+tc.query, nil)
			r = r.WithContext(adminaction.WithContext(rbac.WithActor(r.Context(), uuid.New()), op))
			w := httptest.NewRecorder()
			source := ledgerHTTPSource{head: ledgerproof.Head{Seq: 4, MaxSeq: 4, Hash: hash}, steps: []ledgerproof.Step{tc.step}}
			s.runLedgerVerification(w, r, func(ctx context.Context, p ledgerproof.Params) (ledgerproof.Result, error) {
				return ledgerproof.Verify(ctx, source, p)
			})
			var response adminLedgerVerifyResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || response.Verified != tc.verified || response.RestartRequired != tc.restart || (tc.reason != "" && (response.FailureReason == nil || *response.FailureReason != tc.reason)) {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if op.Event.EventType != audit.EventAdminChainVerified || op.Event.ActionStatus != tc.status || op.Event.Security != nil || op.Event.Payload["verification_scope"] != "database_relative_retained_segment" {
				t.Fatalf("audit %+v", op.Event)
			}
			if tc.name == "all purged" && (response.Checked != 0 || response.PurgedCount != 2 || response.PurgedSpans != 1 || !response.Complete || response.BrokenAtSeq != nil) {
				t.Fatalf("no-content status %s", w.Body.String())
			}
			for _, forbidden := range []string{record.ID, record.AccountRef, "192.0.2.123", "private-event", "account_ref", "payload", "identity_blind_index"} {
				if strings.Contains(w.Body.String(), forbidden) {
					t.Fatalf("leaked %s", forbidden)
				}
			}
		})
	}
}
