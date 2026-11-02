//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func TestAdminLegalPostDeletionDisclosureIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	ctx := context.Background()
	indexer, err := blindindex.New(bytes.Repeat([]byte{0x62}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	holds, err := legalhold.New(db.New(f.pool), f.enc, legalhold.WithReleasedMetadataRetention(time.Hour), legalhold.WithLookup(indexer, true))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.LegalHold = holds
	f.srv = New(f.srv.cfg, nil, f.srv.deps)
	index := indexer.Compute(f.target.Email)
	ip, agent := "203.0.113.42", "private-client-agent"
	eventID := uuid.New()
	timestamp := audit.NormalizeChainTime(time.Now())
	retainUntil := audit.NormalizeChainTime(time.Now().Add(time.Hour))
	leaf, err := audit.LeafLedger(audit.LedgerRecord{
		ID: eventID.String(), AccountRef: f.target.ID.String(), IdentityBlindIndex: &index,
		BlindIndexVersion: indexer.Version(), EventType: audit.EventLoginSucceeded,
		ClientIP: &ip, UserAgent: &agent, Timestamp: timestamp, RetainUntil: retainUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.New(f.pool).InsertSecurityEventWithChain(ctx, db.InsertSecurityEventWithChainParams{
		EventID: eventID, LeafHash: leaf.Bytes(),
		ChainHash:  audit.ChainLedger(audit.LedgerGenesis(), leaf).Bytes(),
		AccountRef: f.target.ID, IdentityBlindIndex: &index, BlindIndexVersion: indexer.Version(),
		EventType: audit.EventLoginSucceeded, ClientIp: &ip, UserAgent: &agent,
		Timestamp:   pgtype.Timestamptz{Time: timestamp, Valid: true},
		RetainUntil: pgtype.Timestamptz{Time: retainUntil, Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, "DELETE FROM users WHERE id=$1", f.target.ID); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"identifier_type": "email", "identifier": f.target.Email, "requesting_authority": "private-court-789",
		"case_reference": "private-case-123", "purpose": "private-purpose-456", "start_time": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"end_time": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	send := func() *httptest.ResponseRecorder {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return f.request(t, "dpo", "POST", "/legal-inquiry/lookup", string(encoded), f.grant(t, "dpo"))
	}
	w := send()
	if w.Code != 200 {
		t.Fatalf("post-delete lookup: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		Items    []adminLedgerEventResponse `json:"items"`
		Coverage legalhold.Coverage         `json:"coverage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 1 || response.Items[0].ID != eventID || response.Items[0].AccountRef != f.target.ID || response.Coverage.Note == "" {
		t.Fatalf("wrong disclosure or absent coverage: %s", w.Body.String())
	}
	for _, forbidden := range []string{f.target.Email, index, ip, agent, "identity_blind_index", "client_ip", "user_agent", "private-case-123"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("default disclosure leaked %q", forbidden)
		}
	}
	var payload, encrypted []byte
	err = f.pool.QueryRow(ctx, `SELECT o.payload,c.details_encrypted FROM event_outbox o
		JOIN admin_action_contexts c ON c.action_id=o.id
		WHERE o.payload::jsonb->>'actor_id'=$1 AND o.payload::jsonb->>'event_type'=$2
		ORDER BY o.created_at DESC LIMIT 1`, f.actors["dpo"].UserID, audit.EventLegalInquiryLookup).Scan(&payload, &encrypted)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := f.enc.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	for _, secret := range []string{f.target.Email, index} {
		if bytes.Contains(payload, []byte(secret)) || bytes.Contains(plain, []byte(secret)) {
			t.Fatal("lookup identity persisted in audit or restricted action context")
		}
	}
	for _, secret := range []string{"private-court-789", "private-case-123", "private-purpose-456"} {
		if bytes.Contains(payload, []byte(secret)) || bytes.Contains(encrypted, []byte(secret)) || !bytes.Contains(plain, []byte(secret)) {
			t.Fatal("case context was not restricted to its encrypted record")
		}
	}
	var env audit.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
	if env.Security != nil || env.SubjectID != "" || !strings.Contains(env.Payload, "response_digest") || !strings.Contains(env.Payload, "selected_fields") {
		t.Fatal("disclosure audit lacks bounded scope or contains Class B context")
	}
	body["fields"] = []string{"client_ip"}
	w = send()
	if w.Code != 200 || !strings.Contains(w.Body.String(), ip) || strings.Contains(w.Body.String(), agent) {
		t.Fatalf("explicit minimum field selection: %d %s", w.Code, w.Body.String())
	}
	body["identifier_type"] = "phone"
	if w := send(); w.Code != 400 || !strings.Contains(w.Body.String(), "unsupported_identifier_type") {
		t.Fatalf("phone accepted: %d %s", w.Code, w.Body.String())
	}
	body["identifier_type"] = "email"
	var rejected int
	var operations []uuid.UUID
	failedActions, err := adminaction.New(adminIntegrationBeginFunc(func(ctx context.Context) (pgx.Tx, error) {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		return rejectAuditTx{Tx: tx, reject: func(ctx context.Context, tx pgx.Tx, args []any) bool {
			var env audit.Envelope
			if err := json.Unmarshal([]byte(args[2].(string)), &env); err != nil {
				t.Fatal(err)
			}
			if env.EventType != audit.EventLegalInquiryLookup || env.ActionStatus != audit.StatusSuccess {
				t.Fatal("injection did not reach a successful disclosure audit")
			}
			var encrypted []byte
			if err := tx.QueryRow(ctx, "SELECT details_encrypted FROM admin_action_contexts WHERE action_id=$1", env.EventID).Scan(&encrypted); err != nil || len(encrypted) == 0 {
				t.Fatalf("injection preceded restricted disclosure-context storage: %v", err)
			}
			rejected++
			operations = append(operations, env.EventID)
			return true
		}}, nil
	}), f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = failedActions
	touches := f.sessionStore.touches.Load()
	w = send()
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "{\"error\":\"audit_unavailable\"}\n" {
		t.Fatalf("unaudited legal disclosure: %d %s", w.Code, w.Body.String())
	}
	if rejected != 1 || f.sessionStore.touches.Load() != touches {
		t.Fatal("failed disclosure did not reach audit or renewed session activity")
	}
	for _, id := range operations {
		var remnants int
		if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM admin_action_contexts WHERE action_id=$1) +
			(SELECT count(*) FROM event_outbox WHERE id=$1)`, id).Scan(&remnants); err != nil || remnants != 0 {
			t.Fatalf("failed disclosure retained private context or success intent: %d %v", remnants, err)
		}
	}
}

func TestAdminLegalAuditFailureRollsBackIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	account := uuid.New()
	body := `{"account_ref":"` + account.String() + `","reason":"confidential-hold-reason","requesting_authority":"private-authority","legal_basis":"private-order"}`
	w := f.request(t, "dpo", "POST", "/legal-holds", body, f.grant(t, "dpo"))
	if w.Code != 201 {
		t.Fatalf("initial hold: %d %s", w.Code, w.Body.String())
	}
	var hold adminLegalHoldResponse
	if err := json.Unmarshal(w.Body.Bytes(), &hold); err != nil {
		t.Fatal(err)
	}
	var rejected int
	var operations []uuid.UUID
	failedActions, err := adminaction.New(adminIntegrationBeginFunc(func(ctx context.Context) (pgx.Tx, error) {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		return rejectAuditTx{Tx: tx, reject: func(ctx context.Context, tx pgx.Tx, args []any) bool {
			var env audit.Envelope
			if err := json.Unmarshal([]byte(args[2].(string)), &env); err != nil || env.ActionStatus != audit.StatusSuccess {
				t.Fatalf("injection did not reach a tentative legal success: %v", err)
			}
			if env.EventType != "legal.holds.list" {
				var metadata struct {
					HoldID uuid.UUID `json:"hold_id"`
				}
				if err := json.Unmarshal([]byte(env.Payload), &metadata); err != nil {
					t.Fatal(err)
				}
				row, err := db.New(tx).GetLegalHold(ctx, metadata.HoldID)
				if err != nil || row.AccountRef != account || len(row.DetailsEncrypted) == 0 || row.Reason != nil {
					t.Fatalf("injection preceded encrypted legal business state: %v", err)
				}
				if env.EventType == audit.EventLegalHoldReleased {
					if row.IsActive || !row.ReleasedAt.Valid || metadata.HoldID != hold.ID {
						t.Fatal("injection preceded tentative release")
					}
				} else if !row.IsActive || metadata.HoldID == hold.ID {
					t.Fatal("injection preceded independent hold creation")
				}
			}
			rejected++
			operations = append(operations, env.EventID)
			return true
		}}, nil
	}), f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = failedActions
	touches := f.sessionStore.touches.Load()
	for _, call := range []struct{ method, path, body string }{
		{"POST", "/legal-holds", body},
		{"POST", "/preservation-requests", `{"account_ref":"` + account.String() + `","reason":"confidential-hold-reason","requesting_authority":"private-authority"}`},
		{"DELETE", "/legal-holds/" + hold.ID.String(), ""},
		{"GET", "/legal-holds?account_ref=" + account.String(), ""},
	} {
		w := f.request(t, "dpo", call.method, call.path, call.body, f.grant(t, "dpo"))
		if w.Code != http.StatusServiceUnavailable || w.Body.String() != "{\"error\":\"audit_unavailable\"}\n" {
			t.Fatalf("%s %s did not fail closed: %d %s", call.method, call.path, w.Code, w.Body.String())
		}
		if f.sessionStore.touches.Load() != touches {
			t.Fatal("failed legal audit renewed session activity")
		}
	}
	var count, active int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*),count(*) FILTER (WHERE is_active) FROM legal_holds WHERE account_ref=$1", account).Scan(&count, &active); err != nil {
		t.Fatal(err)
	}
	if count != 1 || active != 1 {
		t.Fatalf("audit failure committed creation or release: total=%d active=%d", count, active)
	}
	if rejected != 4 {
		t.Fatalf("wrong legal audit failure boundary: rejected=%d", rejected)
	}
	for _, id := range operations {
		var remnants int
		if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM admin_action_contexts WHERE action_id=$1) +
			(SELECT count(*) FROM event_outbox WHERE id=$1)`, id).Scan(&remnants); err != nil || remnants != 0 {
			t.Fatalf("failed legal operation retained context or success intent: %d %v", remnants, err)
		}
	}
}

func TestAdminLegalCommittedWritesSurviveSessionRenewalFailureIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	for _, tc := range []struct{ path, kind, body string }{
		{"/legal-holds", legalhold.KindHold, `,"legal_basis":"order"`},
		{"/preservation-requests", legalhold.KindPreservation, ""},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			t.Cleanup(func() { f.sessionStore.touchErr = nil })
			account, key := uuid.New(), uuid.New()
			body := `{"account_ref":"` + account.String() + `","reason":"sealed-intake","requesting_authority":"court"` + tc.body + `}`
			f.sessionStore.touchErr = session.ErrStoreUnavailable
			w := f.requestWithKey(t, "dpo", http.MethodPost, tc.path, body, f.grant(t, "dpo"), key.String())
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "temporarily_unavailable") || strings.Contains(w.Body.String(), "sealed-intake") || strings.Contains(w.Body.String(), account.String()) {
				t.Fatalf("post-commit renewal failure disclosed a response: %d %s", w.Code, w.Body.String())
			}
			q := db.New(f.pool)
			row, err := q.GetLegalHoldByRequest(t.Context(), db.GetLegalHoldByRequestParams{
				AccountRef: account, RequestKind: tc.kind, IdempotencyKey: uuid.NullUUID{UUID: key, Valid: true},
			})
			if err != nil || !row.IsActive {
				t.Fatalf("renewal failure unexpectedly rolled back committed creation: %v", err)
			}
			var successes int
			if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM event_outbox WHERE admin_action
				AND payload::jsonb->>'action_status'='success' AND (payload::jsonb->>'payload')::jsonb->>'hold_id'=$1`, row.ID.String()).Scan(&successes); err != nil || successes != 1 {
				t.Fatalf("committed creation lost its durable audit: count=%d err=%v", successes, err)
			}
			f.sessionStore.touchErr = nil
			w = f.requestWithKey(t, "dpo", http.MethodPost, tc.path, body, f.grant(t, "dpo"), key.String())
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"replayed":true`) || !strings.Contains(w.Body.String(), row.ID.String()) {
				t.Fatalf("explicit original-key recovery did not replay: %d %s", w.Code, w.Body.String())
			}
			f.sessionStore.touchErr = session.ErrStoreUnavailable
			w = f.request(t, "dpo", http.MethodDelete, "/legal-holds/"+row.ID.String(), "", f.grant(t, "dpo"))
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "temporarily_unavailable") {
				t.Fatalf("lost release response: %d %s", w.Code, w.Body.String())
			}
			released, err := q.GetLegalHold(t.Context(), row.ID)
			if err != nil || released.IsActive || !released.ReleasedAt.Valid || !released.ReleasedBy.Valid {
				t.Fatalf("renewal failure unexpectedly rolled back committed release: %v", err)
			}
			if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM event_outbox WHERE admin_action
				AND payload::jsonb->>'event_type'=$1 AND payload::jsonb->>'action_status'='success'
				AND (payload::jsonb->>'payload')::jsonb->>'hold_id'=$2`, audit.EventLegalHoldReleased, row.ID.String()).Scan(&successes); err != nil || successes != 1 {
				t.Fatalf("committed release lost its durable audit: count=%d err=%v", successes, err)
			}
			f.sessionStore.touchErr = nil
			w = f.request(t, "dpo", http.MethodDelete, "/legal-holds/"+row.ID.String(), "", f.grant(t, "dpo"))
			if w.Code != http.StatusNoContent {
				t.Fatalf("explicit release recovery: %d %s", w.Code, w.Body.String())
			}
			again, err := q.GetLegalHold(t.Context(), row.ID)
			if err != nil || again.IsActive || !again.ReleasedAt.Time.Equal(released.ReleasedAt.Time) || again.ReleasedBy != released.ReleasedBy {
				t.Fatalf("release retry changed original attribution: %v", err)
			}
			w = f.requestWithKey(t, "dpo", http.MethodPost, tc.path, body, f.grant(t, "dpo"), key.String())
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"is_active":false`) || !strings.Contains(w.Body.String(), `"replayed":true`) {
				t.Fatalf("released create recovery reactivated a hold: %d %s", w.Code, w.Body.String())
			}
			var count int
			if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM legal_holds WHERE account_ref=$1", account).Scan(&count); err != nil || count != 1 {
				t.Fatalf("lost response duplicated its independent request: %d %v", count, err)
			}
		})
	}
}

func TestAdminLegalLookupExactHighSequencesIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	q := db.New(tx)
	indexer, err := blindindex.New(bytes.Repeat([]byte{0x62}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	holds, err := legalhold.New(q, f.enc, legalhold.WithReleasedMetadataRetention(time.Hour), legalhold.WithLookup(indexer, true))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.LegalHold = holds
	index := indexer.Compute(f.target.Email)
	seqs := []int64{9007199254740993, math.MaxInt64 - 1, math.MaxInt64}
	at := audit.NormalizeChainTime(time.Now())
	retain := at.Add(time.Hour)
	previous := audit.LedgerGenesis()
	var nodes []db.InsertSecurityLedgerChainParams
	var records []db.InsertSecurityEventsParams
	for _, seq := range seqs {
		id := uuid.New()
		leaf, err := audit.LeafLedger(audit.LedgerRecord{ID: id.String(), AccountRef: f.target.ID.String(), IdentityBlindIndex: &index,
			EventType: audit.EventLoginSucceeded, Timestamp: at, RetainUntil: retain})
		if err != nil {
			t.Fatal(err)
		}
		previous = audit.ChainLedger(previous, leaf)
		nodes = append(nodes, db.InsertSecurityLedgerChainParams{Seq: seq, EventID: id, LeafHash: leaf.Bytes(), ChainHash: previous.Bytes()})
		records = append(records, db.InsertSecurityEventsParams{Seq: seq, AccountRef: f.target.ID, IdentityBlindIndex: &index, EventType: audit.EventLoginSucceeded,
			Timestamp: pgtype.Timestamptz{Time: at, Valid: true}, RetainUntil: pgtype.Timestamptz{Time: retain, Valid: true}})
	}
	// Rolled-back explicit positions exercise MaxInt64 without exhausting the
	// shared signer sequence or leaving a fabricated chain head.
	if n, err := q.InsertSecurityLedgerChain(t.Context(), nodes); err != nil || n != int64(len(nodes)) {
		t.Fatalf("insert high-position chain: %d %v", n, err)
	}
	if n, err := q.InsertSecurityEvents(t.Context(), records); err != nil || n != int64(len(records)) {
		t.Fatalf("insert high-position payloads: %d %v", n, err)
	}
	body := adminLegalInquiryRequest{IdentifierType: "email", Identifier: f.target.Email, RequestingAuthority: "court", CaseReference: "case",
		Purpose: "exact coordinates", StartTime: at.Add(-time.Hour).Format(time.RFC3339Nano), EndTime: at.Format(time.RFC3339Nano), Limit: 1, Fields: []string{}}
	actor := uuid.MustParse(f.actors["dpo"].UserID)
	var observed time.Time
	for i, seq := range seqs {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/legal-inquiry/lookup", bytes.NewReader(encoded))
		op := &adminaction.Operation{ID: uuid.New(), Tx: tx, Queries: q}
		r = r.WithContext(adminaction.WithContext(rbac.WithActor(r.Context(), actor), op))
		w := httptest.NewRecorder()
		f.srv.handleAdminLegalInquiryLookup().ServeHTTP(w, r)
		var page struct {
			Items []struct {
				ID  uuid.UUID `json:"id"`
				Seq string    `json:"seq"`
			} `json:"items"`
			NextCursor string `json:"next_cursor"`
			Coverage   struct {
				ThroughSeq string    `json:"through_seq"`
				ObservedAt time.Time `json:"observed_at"`
			} `json:"coverage"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 ||
			page.Items[0].ID != nodes[i].EventID || page.Items[0].Seq != strconv.FormatInt(seq, 10) || page.Coverage.ThroughSeq != "9223372036854775807" {
			t.Fatalf("SQL-backed attribution page lost exact coordinates at %d: %d %s", i, w.Code, w.Body.String())
		}
		if i == 0 {
			observed = page.Coverage.ObservedAt
		}
		if observed.IsZero() || !page.Coverage.ObservedAt.Equal(observed) || (page.NextCursor != "") != (i < len(seqs)-1) {
			t.Fatal("exact-coordinate continuation changed its coverage or exhausted early")
		}
		if op.Event.Payload["through_seq"] != int64(math.MaxInt64) {
			t.Fatal("wire strings changed internal numeric audit coordinates")
		}
		body.Cursor = page.NextCursor
	}
}

func TestAdminLegalCapabilitiesMountsAndLegalOnlyGrantsIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	indexer, err := blindindex.New(bytes.Repeat([]byte{0x62}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	// These variants test wiring, not signer acceptance. The real operator
	// probe and canonical-v2 fixture are separate integration/browser gates.
	verified, err := legalhold.New(db.New(f.pool), f.enc, legalhold.WithReleasedMetadataRetention(time.Hour), legalhold.WithLookup(indexer, true))
	if err != nil {
		t.Fatal(err)
	}
	unverified, err := legalhold.New(db.New(f.pool), f.enc, legalhold.WithReleasedMetadataRetention(time.Hour), legalhold.WithLookup(indexer, false))
	if err != nil {
		t.Fatal(err)
	}
	deps := f.srv.deps
	all := adminCapabilities{AuditLogsRead: true, AuditChainVerify: true, LedgerVerify: true,
		LegalHoldsRead: true, LegalHoldsApply: true, LegalHoldsRelease: true, PreservationRequestsCreate: true, LegalInquiryLookup: true}
	for _, tc := range []struct {
		name  string
		holds *legalhold.Service
		step  bool
		want  adminCapabilities
	}{
		{"missing service", nil, true, adminCapabilities{AuditLogsRead: true, AuditChainVerify: true, LedgerVerify: true}},
		{"no indexer", deps.LegalHold, true, adminCapabilities{AuditLogsRead: true, AuditChainVerify: true, LedgerVerify: true, LegalHoldsRead: true, LegalHoldsApply: true, LegalHoldsRelease: true, PreservationRequestsCreate: true}},
		{"unverified indexer", unverified, true, adminCapabilities{AuditLogsRead: true, AuditChainVerify: true, LedgerVerify: true, LegalHoldsRead: true, LegalHoldsApply: true, LegalHoldsRelease: true, PreservationRequestsCreate: true}},
		{"lookup verified", verified, true, all},
		{"absent step up", verified, false, adminCapabilities{AuditLogsRead: true, AuditChainVerify: true, LedgerVerify: true, LegalHoldsRead: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := deps
			current.LegalHold = tc.holds
			if !tc.step {
				current.StepUp = nil
			}
			f.srv = New(f.srv.cfg, nil, current)
			w := f.request(t, "dpo", http.MethodGet, "/capabilities", "", "")
			var result adminCapabilitiesResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Capabilities != tc.want {
				t.Fatalf("legal route capture timing or availability changed: %d %s", w.Code, w.Body.String())
			}
			for _, route := range []struct {
				method, path string
				mounted      bool
			}{
				{http.MethodGet, "/legal-holds?account_ref=" + f.target.ID.String(), tc.want.LegalHoldsRead},
				{http.MethodPost, "/legal-holds", tc.want.LegalHoldsApply},
				{http.MethodDelete, "/legal-holds/" + uuid.NewString(), tc.want.LegalHoldsRelease},
				{http.MethodPost, "/preservation-requests", tc.want.PreservationRequestsCreate},
				{http.MethodPost, "/legal-inquiry/lookup", tc.want.LegalInquiryLookup},
			} {
				w := f.request(t, "dpo", route.method, route.path, "", "")
				if !route.mounted {
					if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
						t.Fatalf("unavailable flag has an accessible route: %s %s status=%d", route.method, route.path, w.Code)
					}
				} else if route.method == http.MethodGet {
					if w.Code != http.StatusOK {
						t.Fatalf("eligible read incorrectly needs step-up: %d", w.Code)
					}
				} else if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "insufficient_user_authentication") {
					t.Fatalf("advertised write/lookup lacks its step-up gate: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
	deps.LegalHold = verified
	f.srv = New(f.srv.cfg, nil, deps)
	actor := uuid.MustParse(f.actors["ordinary"].UserID)
	if _, err := f.pool.Exec(t.Context(), "UPDATE users SET is_mfa_enabled=true WHERE id=$1", actor); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		permission string
		want       adminCapabilities
	}{
		{permLegalHoldsRead, adminCapabilities{LegalHoldsRead: true}},
		{permLegalHoldsWrite, adminCapabilities{LegalHoldsApply: true, LegalHoldsRelease: true, PreservationRequestsCreate: true}},
		{permLegalInquiryLookup, adminCapabilities{LegalInquiryLookup: true}},
	} {
		t.Run(tc.permission, func(t *testing.T) {
			q := db.New(f.pool)
			role := "legal_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err := q.CreateRole(t.Context(), db.CreateRoleParams{ID: role, Description: "isolated legal-only fixture"}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = q.DeleteRole(context.Background(), role) })
			if err := q.AddPermissionToRole(t.Context(), db.AddPermissionToRoleParams{RoleID: role, PermissionID: tc.permission}); err != nil {
				t.Fatal(err)
			}
			// Synthetic single-permission roles exercise admission without changing
			// seeded roles or extending the production operator's fixed role list.
			if err := q.AssignRoleToUser(t.Context(), db.AssignRoleToUserParams{UserID: actor, RoleID: role}); err != nil {
				t.Fatal(err)
			}
			w := f.request(t, "ordinary", http.MethodGet, "/capabilities", "", "")
			var result adminCapabilitiesResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Capabilities != tc.want {
				t.Fatalf("legal-only principal rejected or overgranted: %d %s", w.Code, w.Body.String())
			}
			grant := f.grant(t, "ordinary")
			if _, err := q.RemoveRoleFromUser(t.Context(), db.RemoveRoleFromUserParams{UserID: actor, RoleID: role}); err != nil {
				t.Fatal(err)
			}
			if w := f.request(t, "ordinary", http.MethodGet, "/capabilities", "", ""); w.Code != http.StatusForbidden {
				t.Fatalf("revoked legal capability remained: %d", w.Code)
			}
			w = f.request(t, "ordinary", http.MethodPost, "/legal-holds", `{}`, grant)
			if w.Code != http.StatusForbidden || w.Body.String() != "{\"error\":\"forbidden\"}\n" {
				t.Fatal("fresh step-up bypassed revoked live legal permission")
			}
			if _, err := f.step.Validate(t.Context(), grant, f.actors["ordinary"]); err != nil {
				t.Fatalf("permission denial consumed a fresh grant: %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(f.cookies["ordinary"])
			if _, err := f.sessions.Resolve(r); err != nil || len(w.Result().Cookies()) != 0 {
				t.Fatalf("legal capability denial invalidated an ordinary session: %v", err)
			}
		})
	}
}

func TestAdminLegalLookupRequiresFreshGrantPerPageIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	indexer, err := blindindex.New(bytes.Repeat([]byte{0x62}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	holds, err := legalhold.New(db.New(f.pool), f.enc, legalhold.WithReleasedMetadataRetention(time.Hour), legalhold.WithLookup(indexer, true))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.LegalHold = holds
	f.srv = New(f.srv.cfg, nil, f.srv.deps)
	index := indexer.Compute(f.target.Email)
	at := audit.NormalizeChainTime(time.Now())
	for range 2 {
		id, account := uuid.New(), uuid.New()
		leaf, err := audit.LeafLedger(audit.LedgerRecord{ID: id.String(), AccountRef: account.String(), IdentityBlindIndex: &index,
			EventType: audit.EventLoginSucceeded, Timestamp: at, RetainUntil: at.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.New(f.pool).InsertSecurityEventWithChain(t.Context(), db.InsertSecurityEventWithChainParams{
			EventID: id, LeafHash: leaf.Bytes(), ChainHash: audit.ChainLedger(audit.LedgerGenesis(), leaf).Bytes(), AccountRef: account,
			IdentityBlindIndex: &index, EventType: audit.EventLoginSucceeded, Timestamp: pgtype.Timestamptz{Time: at, Valid: true}, RetainUntil: pgtype.Timestamptz{Time: at.Add(time.Hour), Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
	}
	body := adminLegalInquiryRequest{IdentifierType: "email", Identifier: f.target.Email, RequestingAuthority: "court", CaseReference: "case", Purpose: "inquiry",
		StartTime: at.Add(-time.Hour).Format(time.RFC3339Nano), EndTime: at.Format(time.RFC3339Nano), Limit: 1, Fields: []string{}}
	send := func(role, grant string) *httptest.ResponseRecorder {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return f.request(t, role, http.MethodPost, "/legal-inquiry/lookup", string(encoded), grant)
	}
	for _, role := range []string{"support", "moderator", "super_admin"} {
		grant := f.grant(t, role)
		w := send(role, grant)
		if w.Code != http.StatusForbidden || w.Body.String() != "{\"error\":\"forbidden\"}\n" {
			t.Fatalf("non-DPO lookup permitted for %s: %d", role, w.Code)
		}
		if _, err := f.step.Validate(t.Context(), grant, f.actors[role]); err != nil {
			t.Fatal("lookup permission denial consumed step-up")
		}
	}
	grant := f.grant(t, "dpo")
	w := send("dpo", grant)
	var first struct {
		Items      []adminLedgerEventResponse `json:"items"`
		NextCursor string                     `json:"next_cursor"`
		Coverage   legalhold.Coverage         `json:"coverage"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first bounded page: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("legal disclosure omitted privacy response headers")
	}
	body.Cursor = first.NextCursor
	for _, reused := range []string{"", grant} {
		if w := send("dpo", reused); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "insufficient_user_authentication") || strings.Contains(w.Body.String(), "items") {
			t.Fatalf("continuation accepted absent/used authority: %d %s", w.Code, w.Body.String())
		}
	}
	w = send("dpo", f.grant(t, "dpo"))
	var last struct {
		Items      []adminLedgerEventResponse `json:"items"`
		NextCursor string                     `json:"next_cursor"`
		Coverage   legalhold.Coverage         `json:"coverage"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &last) != nil || len(last.Items) != 1 || last.NextCursor != "" ||
		last.Items[0].Seq <= first.Items[0].Seq || last.Items[0].AccountRef == first.Items[0].AccountRef ||
		last.Coverage.ThroughSeq != first.Coverage.ThroughSeq || !last.Coverage.ObservedAt.Equal(first.Coverage.ObservedAt) {
		t.Fatalf("fresh continuation changed identity reference or coverage scope: %d %s", w.Code, w.Body.String())
	}
	body.Purpose = "different scope"
	if w := send("dpo", f.grant(t, "dpo")); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Fatalf("cursor accepted changed inquiry scope: %d %s", w.Code, w.Body.String())
	}
}

func TestAdminLegalStrictHTTPBoundaryIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	account := uuid.New()
	body := `{"account_ref":"` + account.String() + `","reason":"sealed-reason","requesting_authority":"court","legal_basis":"order"}`
	var before int64
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM event_outbox WHERE admin_action").Scan(&before); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, path, body string
		beforeGrant        bool
	}{
		{http.MethodGet, "/legal-holds?account_ref=", "", false},
		{http.MethodGet, "/legal-holds?account_ref=%zz", "", false},
		{http.MethodGet, "/legal-holds?account_ref=" + account.String() + "&account_ref=", "", false},
		{http.MethodGet, "/legal-holds?account_ref=" + account.String() + ";status=all", "", false},
		{http.MethodGet, "/legal-holds?unexpected=private", "", false},
		{http.MethodGet, "/legal-holds?limit=-1", "", false},
		{http.MethodGet, "/legal-holds?status=invalid", "", false},
		{http.MethodPost, "/legal-holds?", body, false},
		{http.MethodPost, "/preservation-requests?", `{}`, false},
		{http.MethodDelete, "/legal-holds/" + uuid.NewString() + "?", "", false},
		{http.MethodPost, "/legal-holds", strings.Replace(body, `"reason":"sealed-reason"`, `"reason":"sealed-reason","reason":"other"`, 1), true},
		{http.MethodPost, "/legal-holds", body + `{}`, true},
		{http.MethodPost, "/legal-holds", strings.TrimSuffix(body, "}") + `,"user_id":"not-an-alias"}`, false},
		{http.MethodPost, "/legal-holds", strings.Replace(body, "sealed-reason", strings.Repeat("x", 4097), 1), false},
		{http.MethodPost, "/legal-holds", strings.Replace(body, "sealed-reason", strings.Repeat("x", 32*1024), 1), false},
		{http.MethodPost, "/preservation-requests", `{"account_ref":"` + account.String() + `","reason":"sealed","requesting_authority":"court","legal_basis":"not-supported"}`, false},
	}
	for _, tc := range cases {
		grant := f.grant(t, "dpo")
		w := f.request(t, "dpo", tc.method, tc.path, tc.body, grant)
		if w.Code != http.StatusBadRequest || w.Body.String() != "{\"error\":\"invalid_request\"}\n" ||
			w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("invalid legal browser request was accepted or disclosed: method=%s status=%d", tc.method, w.Code)
		}
		if tc.beforeGrant {
			if _, err := f.step.Validate(t.Context(), grant, f.actors["dpo"]); err != nil {
				t.Fatalf("ambiguous JSON consumed step-up before the handler: %v", err)
			}
		}
	}
	w := f.requestWithKey(t, "dpo", http.MethodPost, "/legal-holds", body, f.grant(t, "dpo"), "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("create accepted no controlled operation UUID: %d", w.Code)
	}
	var audits, holds int64
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM event_outbox WHERE admin_action").Scan(&audits); err != nil || audits != before+int64(len(cases))+1 {
		t.Fatalf("legal boundary denials were not durably audited: %d %v", audits-before, err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM legal_holds WHERE account_ref=$1", account).Scan(&holds); err != nil || holds != 0 {
		t.Fatalf("invalid legal input created protection: %d %v", holds, err)
	}
}

func TestAdminLegalPreservationPresenceAndReplayObservationIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	key := uuid.NewString()
	body := `{"account_ref":"` + f.target.ID.String() + `","reason":"sealed","requesting_authority":"court","expires_at":"2000-01-01T00:00:00Z"}`
	var holdID uuid.UUID
	for phase := range 3 {
		if phase == 1 {
			if n, err := db.New(f.pool).SoftDeleteUser(t.Context(), f.target.ID); err != nil || n != 1 {
				t.Fatalf("soft-deleted subject fixture: %d %v", n, err)
			}
			id := uuid.New()
			at := audit.NormalizeChainTime(time.Now().Add(-2 * time.Hour))
			retain := at.Add(time.Hour)
			leaf, err := audit.LeafLedger(audit.LedgerRecord{ID: id.String(), AccountRef: f.target.ID.String(), EventType: audit.EventLoginSucceeded, Timestamp: at, RetainUntil: retain})
			if err != nil {
				t.Fatal(err)
			}
			// Presence includes unindexed, expired payloads; it is not a promise
			// of lookup eligibility, completeness, or an immutable snapshot.
			if _, err := db.New(f.pool).InsertSecurityEventWithChain(t.Context(), db.InsertSecurityEventWithChainParams{
				EventID: id, LeafHash: leaf.Bytes(), ChainHash: audit.ChainLedger(audit.LedgerGenesis(), leaf).Bytes(), AccountRef: f.target.ID,
				EventType: audit.EventLoginSucceeded, Timestamp: pgtype.Timestamptz{Time: at, Valid: true}, RetainUntil: pgtype.Timestamptz{Time: retain, Valid: true},
			}); err != nil {
				t.Fatal(err)
			}
		}
		if phase == 2 {
			if _, err := f.pool.Exec(t.Context(), "DELETE FROM users WHERE id=$1", f.target.ID); err != nil {
				t.Fatal(err)
			}
		}
		w := f.requestWithKey(t, "dpo", http.MethodPost, "/preservation-requests", body, f.grant(t, "dpo"), key)
		var result adminPreservationResponse
		wantStatus := http.StatusOK
		if phase == 0 {
			wantStatus = http.StatusCreated
		}
		if w.Code != wantStatus || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Replayed != (phase > 0) ||
			result.AccountPresent != (phase < 2) || result.LedgerEvidencePresent != (phase > 0) || result.ObservedAt.IsZero() || result.Note != preservationNote ||
			!result.Hold.IsActive || result.Hold.Replayed || result.Hold.RequestKind != legalhold.KindPreservation || result.Hold.LegalBasis != legalhold.LegalBasisPreservation ||
			result.Hold.ReviewAt == nil || !result.Hold.ReviewAt.Equal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("preservation presence/replay/advisory-date contract failed at phase %d: status=%d", phase, w.Code)
		}
		if phase == 0 {
			holdID = result.Hold.ID
		} else if result.Hold.ID != holdID {
			t.Fatal("replay changed the independent preservation request")
		}
	}
}
