//go:build integration

package server

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

func TestAdminCapabilitiesMatrixAndAvailabilityIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	for role, want := range map[string]adminCapabilities{
		"support":     {UsersRead: true},
		"moderator":   {UsersRead: true, UsersPII: true, UsersLookup: true, UsersStatusWrite: true},
		"dpo":         {AuditLogsRead: true, AuditChainVerify: true, LedgerVerify: true},
		"super_admin": {AuditChainVerify: true, LedgerVerify: true},
	} {
		response := f.request(t, role, http.MethodGet, "/capabilities", "", "")
		var body adminCapabilitiesResponse
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Capabilities != want {
			t.Fatalf("capabilities mismatch for %s: status %d", role, response.Code)
		}
		if body.Limits.PageSizeDefault != 50 || body.Limits.PageSizeMax != 200 || body.Limits.AuditMaxWindowSeconds != (31*24*time.Hour).Seconds() || body.Limits.ChainVerifyMaxLimit != 5000 {
			t.Fatal("capabilities did not expose effective limits")
		}
		for _, disallowed := range []string{"email", "roles", "legal", "auth_version", "password", "grants", f.actors[role].UserID} {
			if strings.Contains(response.Body.String(), disallowed) {
				t.Fatalf("capability response disclosed %s", disallowed)
			}
		}
	}
	if response := f.request(t, "ordinary", http.MethodGet, "/capabilities", "", ""); response.Code != http.StatusForbidden {
		t.Fatalf("ordinary account capabilities: %d", response.Code)
	}
	actor := uuid.MustParse(f.actors["moderator"].UserID)
	if err := rbac.ProvisionRole(t.Context(), f.srv.deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", actor, "dpo", false); err != nil {
		t.Fatal(err)
	}
	response := f.request(t, "moderator", http.MethodGet, "/capabilities", "", "")
	var combined adminCapabilitiesResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &combined) != nil || combined.Capabilities != (adminCapabilities{true, true, true, true, true, true, true}) {
		t.Fatal("combined grants did not expose their union")
	}
	deps := f.srv.deps
	deps.StepUp = nil
	f.srv = New(f.srv.cfg, nil, deps)
	response = f.request(t, "moderator", http.MethodGet, "/capabilities", "", "")
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &combined) != nil || combined.Capabilities.UsersStatusWrite || !combined.Capabilities.UsersRead {
		t.Fatal("missing step-up did not suppress only status writing")
	}
	if response := f.request(t, "moderator", http.MethodPatch, "/users/"+f.target.ID.String()+"/status", adminStatusBody(t, "banned", "reason", 0), ""); response.Code != http.StatusNotFound {
		t.Fatalf("status route mounted without step-up: %d", response.Code)
	}
	cfg := f.srv.cfg
	cfg.Admin.Enabled = false
	f.srv = New(cfg, nil, deps)
	if response := f.request(t, "support", http.MethodGet, "/capabilities", "", ""); response.Code != http.StatusNotFound {
		t.Fatalf("disabled admin capabilities mounted: %d", response.Code)
	}
}

func TestAdminCapabilitiesRevocationAndRestrictedSessionsIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	actor := uuid.MustParse(f.actors["support"].UserID)
	if err := rbac.ProvisionRole(t.Context(), f.srv.deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", actor, "support", true); err != nil {
		t.Fatal(err)
	}
	if response := f.request(t, "support", http.MethodGet, "/capabilities", "", ""); response.Code != http.StatusForbidden {
		t.Fatalf("revoked capability remained: %d", response.Code)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE users SET status='suspended' WHERE id=$1", uuid.MustParse(f.actors["moderator"].UserID)); err != nil {
		t.Fatal(err)
	}
	if response := f.request(t, "moderator", http.MethodGet, "/capabilities", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("inactive actor discovered capabilities: %d", response.Code)
	}
	w := httptest.NewRecorder()
	current, err := f.sessions.IssueContext(t.Context(), w, session.IssueParams{
		UserID: f.actors["dpo"].UserID, Kind: session.KindRecoveryEnrollment,
		AuthVersion: f.actors["dpo"].AuthVersion, AuthVersionSet: true, DPoPJKT: f.browser.jkt,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.actors["recovery"], f.cookies["recovery"] = current, w.Result().Cookies()[0]
	if response := f.request(t, "recovery", http.MethodGet, "/capabilities", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("recovery session discovered capabilities: %d", response.Code)
	}
}

func TestAdminPanelExactSnapshotsAndQueryKeysIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	if _, err := f.pool.Exec(t.Context(), "UPDATE users SET lifecycle_revision=9223372036854775807 WHERE id=$1", f.target.ID); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, path, body string }{
		{http.MethodGet, "/users", ""},
		{http.MethodGet, "/users/" + f.target.ID.String(), ""},
		{http.MethodPost, "/users/lookup", `{"email":"` + f.target.Email + `"}`},
	} {
		response := f.request(t, "moderator", request.method, request.path, request.body, "")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"lifecycle_revision":"9223372036854775807"`) {
			t.Fatalf("inexact/missing account revision on %s: %d", request.path, response.Code)
		}
	}
	for _, path := range []string{
		"/capabilities?actor=spoofed", "/users?limit=1&limit=2", "/users?unknown=x",
		"/users/" + f.target.ID.String() + "?limit=1",
		"/audit-logs?start_time=2026-01-01T00:00:00Z&end_time=2026-01-02T00:00:00Z&offset=0",
		"/audit-logs/verify?after_seq=0&after_seq=1", "/ledger/verify?unknown=x",
	} {
		role := "moderator"
		if strings.Contains(path, "audit-logs") || strings.Contains(path, "ledger") {
			role = "dpo"
		}
		if response := f.request(t, role, http.MethodGet, path, "", ""); response.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous/unknown query accepted: %s (%d)", path, response.Code)
		}
	}
	if response := f.request(t, "moderator", http.MethodPatch, "/users/"+f.target.ID.String()+"/status?reason=private", adminStatusBody(t, "banned", "reason", 0), f.grant(t, "moderator")); response.Code != http.StatusBadRequest {
		t.Fatal("moderation accepted query parameters")
	}
}

func TestAdminAuditPageExactHighSequencesIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	q := db.New(tx)
	// Explicit positions inside a rolled-back transaction exercise the maximum
	// without exhausting the shared sequence or leaving a fabricated chain head.
	seqs := []int64{9007199254740993, math.MaxInt64 - 1, math.MaxInt64}
	eventType := "admin.test.coordinates_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	actor := uuid.MustParse(f.actors["dpo"].UserID)
	previous := audit.Genesis()
	var nodes []db.InsertAuditLogChainParams
	var records []db.InsertAuditLogsParams
	for _, seq := range seqs {
		record := audit.AuditRecord{
			ID: uuid.NewString(), ActorID: actor.String(), ActorSPIFFEID: audit.APIActorSPIFFEID,
			EventType: eventType, ActionStatus: audit.StatusSuccess, ClientIP: "192.0.2.1",
			UserAgent: "coordinate-test", Payload: `{"fixture":"exact-sequence"}`, Timestamp: at,
		}
		leaf, err := audit.LeafAudit(record)
		if err != nil {
			t.Fatal(err)
		}
		previous = audit.ChainAudit(previous, leaf)
		nodes = append(nodes, db.InsertAuditLogChainParams{Seq: seq, EventID: uuid.MustParse(record.ID), LeafHash: leaf.Bytes(), ChainHash: previous.Bytes()})
		records = append(records, db.InsertAuditLogsParams{
			Seq: seq, ActorID: actor, ActorSpiffeID: record.ActorSPIFFEID, EventType: eventType,
			ActionStatus: record.ActionStatus, ClientIp: record.ClientIP, UserAgent: record.UserAgent,
			Payload: record.Payload, Timestamp: pgtype.Timestamptz{Time: at, Valid: true},
		})
	}
	if n, err := q.InsertAuditLogChain(t.Context(), nodes); err != nil || n != int64(len(nodes)) {
		t.Fatalf("insert chain fixtures: %d %v", n, err)
	}
	if n, err := q.InsertAuditLogs(t.Context(), records); err != nil || n != int64(len(records)) {
		t.Fatalf("insert audit fixtures: %d %v", n, err)
	}
	var before int64
	for pageIndex, want := range []int64{math.MaxInt64, math.MaxInt64 - 1, 9007199254740993, 0} {
		path := "/api/v1/admin/audit-logs?start_time=2026-01-01T00:00:00Z&end_time=2026-01-02T00:00:00Z&limit=1&event_type=" + eventType
		if before != 0 {
			path += "&before_seq=" + strconv.FormatInt(before, 10)
		}
		r := httptest.NewRequest(http.MethodGet, path, nil)
		op := &adminaction.Operation{ID: uuid.New(), Tx: tx, Queries: q}
		r = r.WithContext(adminaction.WithContext(rbac.WithActor(r.Context(), actor), op))
		w := httptest.NewRecorder()
		f.srv.handleAdminListAuditLogs().ServeHTTP(w, r)
		var page struct {
			Items         []adminAuditLogResponse `json:"items"`
			Limit         int32                   `json:"limit"`
			HasMore       bool                    `json:"has_more"`
			NextBeforeSeq string                  `json:"next_before_seq"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatalf("SQL-backed audit page %d lost exact coordinates: %d %s", pageIndex, w.Code, w.Body.String())
		}
		if page.NextBeforeSeq != strconv.FormatInt(want, 10) || page.Limit != 1 || page.HasMore != (pageIndex < 2) {
			t.Fatalf("SQL-backed cursor failed at page %d: %s", pageIndex, w.Body.String())
		}
		if want == 0 {
			if page.Items == nil || len(page.Items) != 0 {
				t.Fatal("exhausted keyset did not return an empty array")
			}
		} else {
			index := len(nodes) - 1 - pageIndex
			if len(page.Items) != 1 || page.Items[0].Seq != want || page.Items[0].ID != nodes[index].EventID || page.Items[0].Payload != records[index].Payload || page.Items[0].SHA256ChainHash != audit.Digest(nodes[index].ChainHash).Hex() {
				t.Fatalf("SQL-backed audit row changed or pagination repeated a boundary: page %d", pageIndex)
			}
		}
		if op.Event.Payload["before_seq"] != before || op.Event.Payload["next_before_seq"] != want {
			t.Fatal("wire string coordinates changed numeric durable audit metadata")
		}
		before = want
	}
}

func TestAdminConcurrentModeratorsRejectStaleRevisionIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	otherActor := uuid.MustParse(f.actors["ordinary"].UserID)
	if _, err := f.pool.Exec(t.Context(), "UPDATE users SET is_mfa_enabled=true WHERE id=$1", otherActor); err != nil {
		t.Fatal(err)
	}
	if err := rbac.ProvisionRole(t.Context(), f.srv.deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", otherActor, "moderator", false); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM event_outbox WHERE admin_action").Scan(&before); err != nil {
		t.Fatal(err)
	}
	var requests []*http.Request
	for i, role := range []string{"moderator", "ordinary"} {
		status := []string{"suspended", "banned"}[i]
		r := httptest.NewRequest(http.MethodPatch, "https://identity.example/api/v1/admin/users/"+f.target.ID.String()+"/status", strings.NewReader(adminStatusBody(t, status, "concurrent decision", 0)))
		f.browser.authorize(t, r, f.actors[role], f.cookies[role])
		r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t, role))
		requests = append(requests, r)
	}
	start := make(chan struct{})
	results := make(chan int, 2)
	for _, request := range requests {
		go func() {
			<-start
			response := httptest.NewRecorder()
			f.srv.Handler().ServeHTTP(response, request)
			results <- response.Code
		}()
	}
	close(start)
	counts := map[int]int{}
	for range 2 {
		counts[<-results]++
	}
	if counts[http.StatusNoContent] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent decisions overwrote one another: %v", counts)
	}
	user, err := db.New(f.pool).GetUserByIDForAdmin(t.Context(), f.target.ID)
	if err != nil || user.LifecycleRevision != 1 || user.AuthVersion != f.target.AuthVersion+1 {
		t.Fatalf("stale decision changed account versions: %v", err)
	}
	var audits, events int64
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM event_outbox WHERE admin_action").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1", f.target.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if audits != before+2 || events != 1 {
		t.Fatalf("separate failure audit or atomic lifecycle intent missing: %d/%d", audits-before, events)
	}
}

func TestAdminProfileAndABAChangesInvalidatePinnedRevisionIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	grant := f.grant(t, "moderator")
	profiles, err := profile.New(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.Update(t.Context(), f.target.ID, f.target.AuthVersion, "Revised profile", "0"); err != nil {
		t.Fatal(err)
	}
	path := "/users/" + f.target.ID.String() + "/status"
	if response := f.request(t, "moderator", http.MethodPatch, path, adminStatusBody(t, "banned", "stale", 0), grant); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "account_conflict") {
		t.Fatalf("profile change failed to invalidate pin: %d", response.Code)
	}
	for i, status := range []string{"suspended", "active"} {
		if response := f.request(t, "moderator", http.MethodPatch, path, adminStatusBody(t, status, "ABA test", int64(i+1)), f.grant(t, "moderator")); response.Code != http.StatusNoContent {
			t.Fatalf("valid transition rejected: %d", response.Code)
		}
	}
	if response := f.request(t, "moderator", http.MethodPatch, path, adminStatusBody(t, "banned", "old active status", 1), f.grant(t, "moderator")); response.Code != http.StatusConflict {
		t.Fatalf("ABA status accepted old revision: %d", response.Code)
	}
	user, err := db.New(f.pool).GetUserByIDForAdmin(t.Context(), f.target.ID)
	if err != nil || user.Status != "active" || user.LifecycleRevision != 3 {
		t.Fatalf("conflict mutated final account state: %v", err)
	}
}

func TestAdminPinnedTargetsRemainServerAuthoritativeIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	for _, status := range []string{"pending_verification", "pending_deletion"} {
		target := f.user(t)
		if _, err := f.pool.Exec(t.Context(), "UPDATE users SET status=$2 WHERE id=$1", target.ID, status); err != nil {
			t.Fatal(err)
		}
		response := f.request(t, "moderator", http.MethodPatch, "/users/"+target.ID.String()+"/status", adminStatusBody(t, "banned", "ineligible", 0), f.grant(t, "moderator"))
		if response.Code != http.StatusConflict {
			t.Fatalf("ineligible %s target accepted: %d", status, response.Code)
		}
	}
	for _, target := range []string{f.actors["moderator"].UserID, f.actors["dpo"].UserID} {
		response := f.request(t, "moderator", http.MethodPatch, "/users/"+target+"/status", adminStatusBody(t, "banned", "protected", 0), f.grant(t, "moderator"))
		if response.Code != http.StatusForbidden || response.Body.String() != "{\"error\":\"forbidden\"}\n" {
			t.Fatalf("self/protected account rejection changed: %d", response.Code)
		}
	}
	grant := f.grant(t, "moderator")
	if err := rbac.ProvisionRole(context.Background(), f.srv.deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", uuid.MustParse(f.actors["moderator"].UserID), "moderator", true); err != nil {
		t.Fatal(err)
	}
	response := f.request(t, "moderator", http.MethodPatch, "/users/"+f.target.ID.String()+"/status", adminStatusBody(t, "banned", "revoked", 0), grant)
	if response.Code != http.StatusForbidden {
		t.Fatalf("grant bypassed revoked live permission: %d", response.Code)
	}
}

type adminCommitBarrierTx struct {
	pgx.Tx
	ready  chan<- uint32
	resume <-chan struct{}
}

func (tx adminCommitBarrierTx) Commit(ctx context.Context) error {
	tx.ready <- tx.Conn().PgConn().PID()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tx.resume:
		return tx.Tx.Commit(ctx)
	}
}

func TestAdminPrivilegedTargetGrantWinsModerationRaceIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	if _, err := f.pool.Exec(t.Context(), "UPDATE users SET is_mfa_enabled=true WHERE id=$1", f.target.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	ready, resume := make(chan uint32, 1), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	var workers sync.WaitGroup
	defer func() { release(); cancel(); workers.Wait() }()
	grantActions, err := adminaction.New(adminIntegrationBeginFunc(func(ctx context.Context) (pgx.Tx, error) {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		return adminCommitBarrierTx{Tx: tx, ready: ready, resume: resume}, nil
	}), f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPatch, "https://identity.example/api/v1/admin/users/"+f.target.ID.String()+"/status", strings.NewReader(adminStatusBody(t, "banned", "pinned before role grant", f.target.LifecycleRevision)))
	r = r.WithContext(ctx)
	f.browser.authorize(t, r, f.actors["moderator"], f.cookies["moderator"])
	r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t, "moderator"))
	granted := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		granted <- rbac.ProvisionRole(ctx, grantActions, uuid.New(), "spiffe://identity.test/operator", f.target.ID, "dpo", false)
	}()
	var holder uint32
	select {
	case holder = <-ready:
	case err := <-granted:
		t.Fatalf("role grant failed before the commit barrier: %v", err)
	case <-ctx.Done():
		t.Fatal("role grant did not reach its commit barrier")
	}
	moderated := make(chan *httptest.ResponseRecorder, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)
		moderated <- w
	}()
	// Observe the real shared advisory-lock wait before committing the grant;
	// scheduling two goroutines alone would not establish this race ordering.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE wait_event_type='Lock' AND wait_event='advisory' AND $1::int=ANY(pg_blocking_pids(pid)))`, int64(holder)).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case w := <-moderated:
			t.Fatalf("moderation did not wait for the target grant: %d %s", w.Code, w.Body.String())
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("moderation did not reach the shared account lock")
		}
	}
	release()
	select {
	case err := <-granted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("role grant did not commit")
	}
	select {
	case w := <-moderated:
		if w.Code != http.StatusForbidden || w.Body.String() != "{\"error\":\"forbidden\"}\n" {
			t.Fatalf("racing protected-role grant was ignored or disclosed: %d %s", w.Code, w.Body.String())
		}
	case <-ctx.Done():
		t.Fatal("moderation did not finish after the role grant")
	}
	q := db.New(f.pool)
	if privileged, err := q.UserHasPrivilegedRole(ctx, f.target.ID); err != nil || !privileged {
		t.Fatalf("racing grant was not persisted: %v", err)
	}
	u, err := q.GetUserByIDForAdmin(ctx, f.target.ID)
	if err != nil || u.Status != f.target.Status || u.AuthVersion != f.target.AuthVersion || u.AuthEpoch != f.target.AuthEpoch || u.LifecycleRevision != f.target.LifecycleRevision {
		t.Fatalf("protected target was mutated after waiting for its grant: %v", err)
	}
	var lifecycleEvents, contexts, successes, failures int64
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1),
		(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1),
		(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2 AND payload::jsonb->>'action_status'='success'),
		(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2 AND payload::jsonb->>'action_status'='failure')`,
		f.target.ID, f.actors["moderator"].UserID).Scan(&lifecycleEvents, &contexts, &successes, &failures); err != nil {
		t.Fatal(err)
	}
	if lifecycleEvents != 0 || contexts != 1 || successes != 0 || failures != 1 {
		t.Fatalf("denied moderation changed lifecycle/context or audit intents: %d/%d/%d/%d", lifecycleEvents, contexts, successes, failures)
	}
}

func TestAdminPinnedTargetsRejectActualDeletionIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	// Prove the predicate matches a real success despite subject-ID sanitization.
	control := f.request(t, "moderator", http.MethodPatch, "/users/"+f.target.ID.String()+"/status", adminStatusBody(t, "suspended", "success intent control", f.target.LifecycleRevision), f.grant(t, "moderator"))
	if control.Code != http.StatusNoContent {
		t.Fatalf("success intent control failed: %d %s", control.Code, control.Body.String())
	}
	var successesBefore int64
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM event_outbox
		WHERE admin_action AND payload::jsonb->>'actor_id'=$1
		AND payload::jsonb->>'event_type'=$2 AND payload::jsonb->>'action_status'='success'`,
		f.actors["moderator"].UserID, audit.EventAdminUserStatusChanged).Scan(&successesBefore); err != nil {
		t.Fatal(err)
	}
	if successesBefore != 1 {
		t.Fatalf("success intent predicate missed the control: count=%d", successesBefore)
	}
	for _, kind := range []string{"soft", "hard"} {
		t.Run(kind, func(t *testing.T) {
			hard := kind == "hard"
			target := f.user(t)
			grant := f.grant(t, "moderator")
			tx, err := f.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := pglock.LockAccount(t.Context(), tx, target.ID); err != nil {
				t.Fatal(err)
			}
			q := db.New(tx)
			if _, err := q.GetUserForUpdateIncludingDeleted(t.Context(), target.ID); err != nil {
				t.Fatal(err)
			}
			if n, err := q.SoftDeleteUser(t.Context(), target.ID); err != nil || n != 1 {
				t.Fatalf("soft-delete fixture: %d %v", n, err)
			}
			if err := lifecycle.EnqueueStatusChange(t.Context(), q, target.ID, target.Status, "pending_deletion"); err != nil {
				t.Fatal(err)
			}
			deleted, err := q.GetUserByIDForAdmin(t.Context(), target.ID)
			if err != nil || !deleted.DeletedAt.Valid || deleted.Status != "pending_deletion" {
				t.Fatalf("target was not actually soft-deleted: %v", err)
			}
			wantStatus, wantCode, wantEvents := http.StatusConflict, "account_not_moderatable", int64(1)
			if hard {
				if n, err := q.HardDeleteUser(t.Context(), db.HardDeleteUserParams{
					ID: target.ID, DeletedAt: pgtype.Timestamptz{Time: deleted.DeletedAt.Time.Add(time.Second), Valid: true},
				}); err != nil || n != 1 {
					t.Fatalf("hard-delete fixture: %d %v", n, err)
				}
				if err := lifecycle.EnqueueDeletion(t.Context(), q, target.ID, deleted.LifecycleRevision); err != nil {
					t.Fatal(err)
				}
				wantStatus, wantCode, wantEvents = http.StatusNotFound, "user_not_found", 2
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			w := f.request(t, "moderator", http.MethodPatch, "/users/"+target.ID.String()+"/status", adminStatusBody(t, "active", "stale reactivation", target.LifecycleRevision), grant)
			if w.Code != wantStatus || w.Body.String() != "{\"error\":\""+wantCode+"\"}\n" {
				t.Fatalf("deleted target accepted stale moderation: %d %s", w.Code, w.Body.String())
			}
			u, err := db.New(f.pool).GetUserByIDForAdmin(t.Context(), target.ID)
			if hard {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("hard-deleted target reappeared: %v", err)
				}
			} else if err != nil || u.Status != deleted.Status || !u.DeletedAt.Valid || !u.DeletedAt.Time.Equal(deleted.DeletedAt.Time) || u.AuthVersion != deleted.AuthVersion || u.AuthEpoch != deleted.AuthEpoch || u.LifecycleRevision != deleted.LifecycleRevision {
				t.Fatalf("soft-deleted target changed after rejected moderation: %v", err)
			}
			var events, contexts, successes int64
			if err := f.pool.QueryRow(t.Context(), `SELECT
				(SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1),
				(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1),
				(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2 AND payload::jsonb->>'event_type'=$3 AND payload::jsonb->>'action_status'='success')`,
				target.ID, f.actors["moderator"].UserID, audit.EventAdminUserStatusChanged).Scan(&events, &contexts, &successes); err != nil {
				t.Fatal(err)
			}
			if events != wantEvents || contexts != 0 || successes != successesBefore {
				t.Fatalf("rejected deletion target gained lifecycle/context/success intents: events=%d contexts=%d successes=%d (before=%d)", events, contexts, successes, successesBefore)
			}
		})
	}
}
