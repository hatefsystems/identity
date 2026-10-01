//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
)

func TestAdminLegalPostDeletionDisclosureIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	ctx := context.Background()
	indexer, err := blindindex.New(bytes.Repeat([]byte{0x62}, 32))
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
	row, err := db.New(f.pool).InsertSecurityEvent(ctx, db.InsertSecurityEventParams{AccountRef: f.target.ID,
		IdentityBlindIndex: &index, EventType: audit.EventLoginSucceeded, ClientIp: &ip, UserAgent: &agent,
		RetainUntil: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, ChainHash: strings.Repeat("a", 64)})
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
		return f.request("dpo", "POST", "/legal-inquiry/lookup", string(encoded), f.grant(t, "dpo"))
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
	if len(response.Items) != 1 || response.Items[0].ID != row.ID || response.Items[0].AccountRef != f.target.ID || response.Coverage.Note == "" {
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
	failedActions, err := adminaction.New(rejectAuditBeginner{f.pool}, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = failedActions
	w = send()
	if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), row.ID.String()) || strings.Contains(w.Body.String(), ip) {
		t.Fatalf("unaudited legal disclosure: %d %s", w.Code, w.Body.String())
	}
}

func TestAdminLegalAuditFailureRollsBackIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	account := uuid.New()
	body := `{"account_ref":"` + account.String() + `","reason":"confidential-hold-reason","requesting_authority":"private-authority","legal_basis":"private-order"}`
	w := f.request("dpo", "POST", "/legal-holds", body, f.grant(t, "dpo"))
	if w.Code != 201 {
		t.Fatalf("initial hold: %d %s", w.Code, w.Body.String())
	}
	var hold adminLegalHoldResponse
	if err := json.Unmarshal(w.Body.Bytes(), &hold); err != nil {
		t.Fatal(err)
	}
	failedActions, err := adminaction.New(rejectAuditBeginner{f.pool}, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = failedActions
	for _, call := range []struct{ method, path, body string }{
		{"POST", "/legal-holds", body},
		{"POST", "/preservation-requests", `{"account_ref":"` + account.String() + `","reason":"confidential-hold-reason","requesting_authority":"private-authority"}`},
		{"DELETE", "/legal-holds/" + hold.ID.String(), ""},
		{"GET", "/legal-holds?account_ref=" + account.String(), ""},
	} {
		w := f.request("dpo", call.method, call.path, call.body, f.grant(t, "dpo"))
		if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), "confidential-hold-reason") {
			t.Fatalf("%s %s did not fail closed: %d %s", call.method, call.path, w.Code, w.Body.String())
		}
	}
	var count, active int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*),count(*) FILTER (WHERE is_active) FROM legal_holds WHERE account_ref=$1", account).Scan(&count, &active); err != nil {
		t.Fatal(err)
	}
	if count != 1 || active != 1 {
		t.Fatalf("audit failure committed creation or release: total=%d active=%d", count, active)
	}
}
