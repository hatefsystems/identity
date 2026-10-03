//go:build integration

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalreport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalworkflow"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

func newWorkflowHTTPIntegration(t *testing.T) *adminIntegration {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	name := "legal_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	dsn, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	dsn.Path = "/" + name
	t.Setenv("DATABASE_URL", dsn.String())
	f := newAdminIntegration(t)
	policy := legalpolicy.Policy{
		ID: uuid.New(), ApprovalReference: "fixture-approval", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry,
		LegacyInventoryReference: "fixture-inventory",
		Workflow: &legalpolicy.WorkflowPolicy{MaxCaseAgeSeconds: 86400, ClosedCaseRetentionSeconds: 3600,
			CaseClock: legalpolicy.ClockCaseExpiry, ReplayFields: legalpolicy.WorkflowReplayFields(), ReplayLifetime: legalpolicy.LifetimeNoExpiry},
	}
	op, err := f.srv.deps.AdminActions.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = op.Rollback(ctx) }()
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/policy-operator"}
	if err := legalpolicy.Install(ctx, op, policy, "test"); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	workflow, err := legalworkflow.New(f.enc, legalworkflow.Config{Enabled: true, PolicyID: policy.ID, Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	reports, err := legalreport.New(legalreport.Config{Enabled: true, PolicyID: policy.ID, Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, deps := f.srv.cfg, f.srv.deps
	cfg.Admin.WorkflowEnabled = true
	cfg.Admin.GovernancePolicyID, cfg.Admin.WorkflowPolicyID = policy.ID.String(), policy.ID.String()
	deps.LegalWorkflow, deps.LegalReports = workflow, reports
	f.srv = New(cfg, nil, deps)
	user := f.user(t)
	if _, err := f.pool.Exec(ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", user.ID); err != nil {
		t.Fatal(err)
	}
	if err := rbac.ProvisionRole(ctx, deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", user.ID, "dpo", false); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	sess, err := f.sessions.IssueContext(ctx, w, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true})
	if err != nil {
		t.Fatal(err)
	}
	f.actors["reviewer"], f.cookies["reviewer"] = sess, w.Result().Cookies()[0]
	return f
}

func workflowHTTPRequest(t *testing.T, f *adminIntegration, role, method, path string, body any, key uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "https://identity.example/api/v1/admin"+path, strings.NewReader(string(data)))
	if cookie := f.cookies[role]; cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("Origin", "https://identity.example")
	r.Header.Set("Idempotency-Key", key.String())
	if method != http.MethodGet {
		r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t, role))
	}
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	return w
}

func workflowResult(t *testing.T, w *httptest.ResponseRecorder, status int) legalworkflow.MutationResult {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), status)
	}
	var result legalworkflow.MutationResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func workflowIntake(subject uuid.UUID) legalworkflow.CreateRequest {
	return legalworkflow.CreateRequest{ReceivedAt: time.Now().UTC().Add(-time.Hour), SubjectIDs: []uuid.UUID{subject},
		Content: legalworkflow.Content{RequestType: "disclosure", AuthorityReference: "task55-private-authority",
			RequestReference: "request-001", LegalBasis: "reviewed fixture basis", MinimumNecessaryScope: "event type only",
			NotificationDisposition: "restricted", NotificationRestriction: "pending review", EvidenceReference: "task55-private-evidence"}}
}

func TestLegalWorkflowHTTPReviewApprovalAndAuditPrivacy(t *testing.T) {
	f := newWorkflowHTTPIntegration(t)
	key := uuid.New()
	intake := workflowIntake(f.target.ID)
	created := workflowResult(t, workflowHTTPRequest(t, f, "dpo", "POST", "/legal-cases", intake, key), 201)
	retry := workflowResult(t, workflowHTTPRequest(t, f, "dpo", "POST", "/legal-cases", intake, key), 200)
	if !retry.Replayed || retry.ID != created.ID {
		t.Fatal("intake replay changed request identity")
	}
	path := "/legal-cases/" + created.ID.String()
	get := workflowHTTPRequest(t, f, "dpo", "GET", path, nil, uuid.New())
	if get.Code != 200 || !strings.Contains(get.Body.String(), "task55-private-authority") {
		t.Fatalf("restricted read: %d %s", get.Code, get.Body.String())
	}
	review := legalworkflow.ReviewRequest{ExpectedVersion: created.Version, ContentRevision: created.ContentRevision, Decision: "accepted", Rationale: "sufficiency and scope checked"}
	accepted := workflowResult(t, workflowHTTPRequest(t, f, "dpo", "POST", path+"/reviews", review, uuid.New()), 200)
	from, until := time.Now().UTC().Add(-2*time.Hour), time.Now().UTC().Add(-time.Hour)
	proposal := legalworkflow.ResponseRequest{ExpectedVersion: accepted.Version, ContentRevision: accepted.ContentRevision,
		Outcome: legalworkflow.OutcomePartialDisclosure, Rationale: "minimum required selection",
		Manifest: legalworkflow.Manifest{RecipientReference: "recipient-001", EvidenceReference: "evidence-001", LegalBasis: "fixture basis",
			SubjectIDs: []uuid.UUID{f.target.ID}, From: &from, Until: &until, Fields: []string{"event_type"},
			Artifacts: []legalworkflow.Artifact{{Reference: "artifact-001", Digest: strings.Repeat("a", 64)}}}}
	prepared := workflowResult(t, workflowHTTPRequest(t, f, "dpo", "POST", path+"/response", proposal, uuid.New()), 200)
	approval := legalworkflow.ApprovalRequest{ExpectedVersion: prepared.Version, ContentRevision: prepared.ContentRevision, ProposalRevision: prepared.ProposalRevision}
	if w := workflowHTTPRequest(t, f, "dpo", "POST", path+"/response/approve", approval, uuid.New()); w.Code != 403 {
		t.Fatalf("self approval: %d %s", w.Code, w.Body.String())
	}
	approved := workflowResult(t, workflowHTTPRequest(t, f, "reviewer", "POST", path+"/response/approve", approval, uuid.New()), 200)
	delivery := legalworkflow.DeliveryRequest{ExpectedVersion: approved.Version, ContentRevision: approved.ContentRevision, ProposalRevision: approved.ProposalRevision, DeliveredAt: time.Now().UTC(), ReceiptReference: "task55-private-receipt"}
	deliveryKey := uuid.New()
	closed := workflowResult(t, workflowHTTPRequest(t, f, "dpo", "POST", path+"/response/delivery", delivery, deliveryKey), 200)
	if closed.Status != "closed" {
		t.Fatalf("delivery did not close: %+v", closed)
	}
	if !workflowResult(t, workflowHTTPRequest(t, f, "dpo", "POST", path+"/response/delivery", delivery, deliveryKey), 200).Replayed {
		t.Fatal("delivery replay lost")
	}
	monthly := workflowHTTPRequest(t, f, "dpo", "GET", "/legal-transparency/monthly?start="+time.Now().UTC().Format("2006-01")+"&months=1", nil, uuid.New())
	if monthly.Code != 200 {
		t.Fatalf("monthly: %d %s", monthly.Code, monthly.Body.String())
	}
	var counts legalreport.MonthlyResult
	if err := json.Unmarshal(monthly.Body.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if len(counts.Months) != 1 || counts.Months[0].Answered != 1 || counts.Months[0].PartialDisclosure != 1 {
		t.Fatalf("delivery counted incorrectly: %+v", counts)
	}
	rows, err := f.pool.Query(context.Background(), `SELECT payload FROM event_outbox WHERE payload LIKE '%/legal-cases%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		seen++
		for _, secret := range []string{"task55-private", created.ID.String(), "response_digest", "record_set_digest", strings.Repeat("a", 64)} {
			if strings.Contains(payload, secret) {
				t.Fatalf("restricted data leaked in audit: %s", secret)
			}
		}
	}
	if rows.Err() != nil || seen == 0 {
		t.Fatalf("workflow audit absent/error: %v", rows.Err())
	}
}

func TestLegalWorkflowHTTPGuardsAndAuditRollback(t *testing.T) {
	f := newWorkflowHTTPIntegration(t)
	for _, role := range []string{"support", "moderator", "super_admin", "ordinary"} {
		for _, path := range []string{"/legal-cases", "/legal-reviews", "/legal-transparency/monthly?start=2026-01&months=1"} {
			if w := workflowHTTPRequest(t, f, role, "GET", path, nil, uuid.New()); w.Code != 403 {
				t.Fatalf("%s %s: %d %s", role, path, w.Code, w.Body.String())
			}
		}
	}
	for _, body := range []string{`{"actor":"spoof"}`, `{} {}`, `{"content":{},"key":"spoof"}`} {
		if w := f.request("dpo", "POST", "/legal-cases", body, f.grant(t, "dpo")); w.Code != 400 {
			t.Fatalf("invalid body accepted: %d %s", w.Code, w.Body.String())
		}
	}
	actions, err := adminaction.New(rejectAuditBeginner{f.pool}, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deps := f.srv.deps
	deps.AdminActions = actions
	f.srv = New(f.srv.cfg, nil, deps)
	if w := workflowHTTPRequest(t, f, "dpo", "POST", "/legal-cases", workflowIntake(f.target.ID), uuid.New()); w.Code != 503 {
		t.Fatalf("audit failure: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM legal_cases").Scan(&count); err != nil || count != 0 {
		t.Fatalf("case survived audit failure count=%d err=%v", count, err)
	}
	if w := workflowHTTPRequest(t, f, "dpo", "GET", "/legal-cases", nil, uuid.New()); w.Code != 503 || strings.Contains(w.Body.String(), "items") {
		t.Fatal("read disclosed before audit commit")
	}
}

func TestLegalTransparencyHTTPReviewedArtifactBytes(t *testing.T) {
	f := newWorkflowHTTPIntegration(t)
	w := workflowHTTPRequest(t, f, "dpo", "POST", "/legal-transparency/reports", legalreport.PrepareRequest{Year: time.Now().UTC().Year() - 1}, uuid.New())
	if w.Code != 201 {
		t.Fatalf("prepare: %d %s", w.Code, w.Body.String())
	}
	var report legalreport.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	path := "/legal-transparency/reports/" + report.ID.String()
	approval := legalreport.ApproveRequest{ExpectedVersion: report.Version, DataVersion: report.DataVersion, PolicyVersion: report.PolicyVersion, Digest: report.Digest}
	if w := workflowHTTPRequest(t, f, "dpo", "POST", path+"/approve", approval, uuid.New()); w.Code != 403 {
		t.Fatalf("self report approval: %d %s", w.Code, w.Body.String())
	}
	w = workflowHTTPRequest(t, f, "reviewer", "POST", path+"/approve", approval, uuid.New())
	if w.Code != 200 {
		t.Fatalf("approval: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	deps := f.srv.deps
	failedActions, err := adminaction.New(rejectAuditBeginner{f.pool}, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	failedDeps := deps
	failedDeps.AdminActions = failedActions
	f.srv = New(f.srv.cfg, nil, failedDeps)
	w = workflowHTTPRequest(t, f, "dpo", "POST", path+"/download", legalreport.DownloadRequest{ExpectedVersion: report.Version}, uuid.New())
	if w.Code != 503 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "schema_version") {
		t.Fatalf("failed audit disclosed artifact: %d %s", w.Code, w.Body.String())
	}
	var status string
	if err := f.pool.QueryRow(context.Background(), "SELECT status FROM legal_transparency_reports WHERE id=$1", report.ID).Scan(&status); err != nil || status != "approved" {
		t.Fatalf("failed download committed status=%s err=%v", status, err)
	}
	var replays int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM legal_transparency_replays WHERE operation='download' AND scope=$1", report.ID.String()).Scan(&replays); err != nil || replays != 0 {
		t.Fatalf("failed download committed replay count=%d err=%v", replays, err)
	}
	f.srv = New(f.srv.cfg, nil, deps)
	if denied := f.request("dpo", "POST", path+"/download", `{}`, ""); denied.Code != 403 {
		t.Fatalf("missing step-up: %d", denied.Code)
	}
	r := httptest.NewRequest("POST", "https://identity.example/api/v1/admin"+path+"/download", strings.NewReader(`{}`))
	r.AddCookie(f.cookies["dpo"])
	r.Header.Set("Origin", "https://untrusted.invalid")
	r.Header.Set("User-Agent", "workflow-early-denial-secret")
	r.Header.Set("Idempotency-Key", uuid.NewString())
	r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t, "dpo"))
	denied := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(denied, r)
	if denied.Code != 403 || denied.Header().Get("Content-Disposition") != "" {
		t.Fatalf("forbidden origin download: %d", denied.Code)
	}
	var leaked bool
	if err := f.pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM event_outbox WHERE payload LIKE '%workflow-early-denial-secret%')").Scan(&leaked); err != nil || leaked {
		t.Fatalf("early denial leaked metadata: %v %v", leaked, err)
	}
	downloadBody, err := json.Marshal(legalreport.DownloadRequest{ExpectedVersion: report.Version})
	if err != nil {
		t.Fatal(err)
	}
	grant := f.grant(t, "dpo")
	w = f.request("dpo", "POST", path+"/download", string(downloadBody), grant)
	if w.Code != 200 {
		t.Fatalf("download: %d %s", w.Code, w.Body.String())
	}
	digest := sha256.Sum256(w.Body.Bytes())
	if hex.EncodeToString(digest[:]) != report.Digest {
		t.Fatal("download differs from approved artifact bytes")
	}
	for _, forbidden := range []string{"data_version", "policy_version", "prepared_by", "approved_by", report.ID.String(), "authority", "case_id"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("artifact leaked %s", forbidden)
		}
	}
	if reused := f.request("dpo", "POST", path+"/download", string(downloadBody), grant); reused.Code != 403 {
		t.Fatalf("reused step-up download: %d", reused.Code)
	}
}

func TestLegalWorkflowOptInAndStepUpBoundaries(t *testing.T) {
	f := newWorkflowHTTPIntegration(t)
	cfg, deps := f.srv.cfg, f.srv.deps
	cfg.Admin.WorkflowEnabled = false
	f.srv = New(cfg, nil, deps)
	if w := f.request("dpo", "GET", "/legal-cases", "", ""); w.Code != 404 {
		t.Fatalf("disabled workflow route exposed: %d %s", w.Code, w.Body.String())
	}
	if w := f.request("dpo", "GET", "/legal-holds", "", ""); w.Code != 200 {
		t.Fatalf("workflow disable broke existing hold access: %d %s", w.Code, w.Body.String())
	}
	cfg.Admin.WorkflowEnabled = true
	deps.StepUp = nil
	f.srv = New(cfg, nil, deps)
	if w := f.request("dpo", "POST", "/legal-cases", `{}`, ""); w.Code != 404 && w.Code != 405 {
		t.Fatalf("mutation mounted without step-up: %d %s", w.Code, w.Body.String())
	}
	if w := f.request("dpo", "GET", "/legal-cases", "", ""); w.Code != 200 {
		t.Fatalf("read unnecessarily requires step-up: %d %s", w.Code, w.Body.String())
	}
}
