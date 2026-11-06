//go:build portalfixture

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func fixturePolicy() legalpolicy.Policy {
	// This artifact is intentionally unusable in production. It enables no legal
	// workflow and never represents an organizational retention approval.
	return legalpolicy.Policy{
		ID: uuid.New(), ApprovalReference: "portal-browser-fixture-only", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry,
	}
}

func fixtureRoles(role string) ([]string, error) {
	switch role {
	case "", "ordinary":
		return nil, nil
	case "support", "moderator", "dpo", "super_admin":
		return []string{role}, nil
	case "combined":
		return []string{"moderator", "dpo", "super_admin"}, nil
	default:
		return nil, errors.New("unsupported fixture role")
	}
}

func fixtureStatus(status string) (string, bool, error) {
	switch status {
	case "", "active":
		return "active", false, nil
	case "suspended", "banned", "pending_verification":
		return status, false, nil
	case "pending_deletion":
		return status, true, nil
	default:
		return "", false, errors.New("unsupported fixture account state")
	}
}

func adminFixture(ctx context.Context, pool *pgxpool.Pool, runID, action string, input request) (any, error) {
	cfg, err := fixtureAuditConfig(runID)
	if err != nil {
		return nil, err
	}
	enc, err := fixtureEncryptor()
	if err != nil {
		return nil, err
	}
	actions, err := adminaction.New(pool, enc, cfg.Subject, time.Hour)
	if err != nil {
		return nil, errors.New("cannot create fixture audit service")
	}
	operator, identity := uuid.New(), "spiffe://portal-fixture.test/operator"
	switch action {
	case "admin-worker-roles":
		return adminWorkerRoles(ctx, pool, runID, cfg.Subject)
	case "admin-policy":
		op, err := actions.Begin(ctx)
		if err != nil {
			return nil, errors.New("cannot begin fixture policy installation")
		}
		defer func() { _ = op.Rollback(ctx) }()
		policy := fixturePolicy()
		op.Event = audit.Event{ActorID: operator, ActorSPIFFEID: identity}
		if err := legalpolicy.Install(ctx, op, policy, "test"); err != nil {
			return nil, errors.New("cannot install fixture-only governance")
		}
		var empty bool
		if err := op.Tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM audit_log_chain) AND NOT EXISTS(SELECT 1 FROM security_ledger_chain)`).Scan(&empty); err != nil || !empty {
			return nil, errors.New("canonical fixture sequences require empty run-owned chains")
		}
		if _, err := op.Tx.Exec(ctx, `INSERT INTO audit_log_head(singleton,seq,chain_hash) VALUES(true,0,$1)`, audit.Genesis().Bytes()); err != nil {
			return nil, errors.New("cannot initialize owned audit head")
		}
		if _, err := op.Tx.Exec(ctx, `INSERT INTO security_ledger_head(singleton,seq,chain_hash) VALUES(true,0,$1)`, audit.LedgerGenesis().Bytes()); err != nil {
			return nil, errors.New("cannot initialize owned security head")
		}
		// Valid gaps and coordinates beyond JavaScript's safe integer range, with
		// all bodies/digests still produced by the unmodified real signer.
		if _, err := op.Tx.Exec(ctx, `SELECT setval('audit_log_chain_seq',9007199254740993,false), setval('security_ledger_chain_seq',9007199254740993,false)`); err != nil {
			return nil, errors.New("cannot initialize fixture sequence gaps")
		}
		if err := op.Commit(ctx); err != nil {
			return nil, errors.New("cannot commit fixture governance and audit intent")
		}
		return map[string]string{"policy_id": policy.ID.String()}, nil
	case "admin-seed":
		roles, err := fixtureRoles(input.Role)
		if err != nil {
			return nil, err
		}
		status, deleted, err := fixtureStatus(input.Status)
		if err != nil {
			return nil, err
		}
		account, err := seedAccount(ctx, pool, runID, input.Credentials, input.TOTP || len(roles) != 0)
		if err != nil {
			return nil, err
		}
		id := uuid.MustParse(account.UserID)
		for _, role := range roles {
			if err := rbac.ProvisionRole(ctx, actions, operator, identity, id, role, false, "test"); err != nil {
				return nil, errors.New("cannot provision fixture operator grant")
			}
		}
		if status != "active" {
			if _, err := pool.Exec(ctx, `UPDATE users SET status=$2,deleted_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE id=$1`, id, status, deleted); err != nil {
				return nil, errors.New("cannot prepare ineligible fixture account")
			}
		}
		return account, nil
	case "admin-delivery":
		var state struct {
			Pending int `json:"pending"`
			Signed  int `json:"signed"`
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE o.published_at IS NULL OR c.event_id IS NULL),count(c.event_id)
			FROM event_outbox o LEFT JOIN audit_log_chain c ON c.event_id=o.id WHERE o.admin_action AND o.subject=$1`, cfg.Subject).Scan(&state.Pending, &state.Signed); err != nil {
			return nil, errors.New("cannot inspect fixture delivery")
		}
		return state, nil
	case "admin-audit-failure":
		var statement string
		switch input.Scenario {
		case "on":
			statement = `CREATE FUNCTION portal_fixture_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.admin_action THEN RAISE EXCEPTION 'fixture audit unavailable'; END IF; RETURN NEW; END $$;
			CREATE TRIGGER portal_fixture_reject_audit BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION portal_fixture_reject_audit()`
		case "off":
			statement = `DROP TRIGGER portal_fixture_reject_audit ON event_outbox; DROP FUNCTION portal_fixture_reject_audit()`
		default:
			return nil, errors.New("unsupported fixture audit failure mode")
		}
		if _, err := pool.Exec(ctx, statement); err != nil {
			return nil, errors.New("cannot change run-owned audit failure fixture")
		}
		return map[string]bool{"configured": true}, nil
	case "admin-tamper":
		// Fixed destructive scenarios only. The CLI has already checked this run's
		// DB name, loopback endpoints and Redis ownership; no SQL comes from stdin.
		if input.Scenario != "ledger-payload-absent" {
			return nil, errors.New("unsupported fixture tampering scenario")
		}
		result, err := pool.Exec(ctx, `DELETE FROM security_event_ledger WHERE seq=(SELECT min(seq) FROM security_event_ledger)`)
		if err != nil || result.RowsAffected() != 1 {
			return nil, errors.New("cannot remove one owned fixture payload")
		}
		return map[string]bool{"tampered": true}, nil
	case "admin-chain-state":
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, errors.New("cannot open owned chain fixture")
		}
		defer func() { _ = tx.Rollback(ctx) }()
		switch input.Scenario {
		case "erased":
			// Test-only database-relative erasure evidence, not a production purge
			// or proof of independent historical authenticity.
			if _, err := tx.Exec(ctx, `INSERT INTO security_ledger_erasures(first_seq,last_seq,operation_id)
				SELECT min(seq),max(seq),$1 FROM security_ledger_chain HAVING count(*)>0`, uuid.New()); err != nil {
				return nil, errors.New("cannot prepare owned erased ledger")
			}
			if _, err := tx.Exec(ctx, `DELETE FROM security_event_ledger`); err != nil {
				return nil, errors.New("cannot erase owned ledger payloads")
			}
		case "empty":
			// Only this armed, run-owned fixture can bypass immutable chain guards.
			// The real API has no reset route and runs unchanged against the result.
			if _, err := tx.Exec(ctx, `ALTER TABLE security_ledger_erasures DISABLE TRIGGER USER;
				ALTER TABLE security_ledger_chain DISABLE TRIGGER USER;
				DELETE FROM security_event_ledger; DELETE FROM security_ledger_erasures; DELETE FROM security_ledger_chain;
				ALTER TABLE security_ledger_erasures ENABLE TRIGGER USER;
				ALTER TABLE security_ledger_chain ENABLE TRIGGER USER`); err != nil {
				return nil, errors.New("cannot clear owned ledger fixture")
			}
			if _, err := tx.Exec(ctx, `UPDATE security_ledger_head SET seq=0,chain_hash=$1`, audit.LedgerGenesis().Bytes()); err != nil {
				return nil, errors.New("cannot initialize owned empty ledger head")
			}
		case "missing-head":
			if _, err := tx.Exec(ctx, `DELETE FROM security_ledger_head`); err != nil {
				return nil, errors.New("cannot prepare owned missing head")
			}
		default:
			return nil, errors.New("unsupported owned chain state")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, errors.New("cannot commit owned chain state")
		}
		return map[string]bool{"configured": true}, nil
	}
	userID, err := uuid.Parse(input.UserID)
	if err != nil || userID == uuid.Nil {
		return nil, errors.New("invalid administrative fixture subject")
	}
	var owned bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND email LIKE $2)`, userID, "%@"+runID+".example.test").Scan(&owned); err != nil || !owned {
		return nil, errors.New("administrative fixture subject is not run-owned")
	}
	switch action {
	case "admin-revision":
		var version, revision int64
		if err := pool.QueryRow(ctx, `SELECT auth_version,lifecycle_revision FROM users WHERE id=$1`, userID).Scan(&version, &revision); err != nil {
			return nil, errors.New("cannot read owned account revision")
		}
		profiles, err := profile.New(pool)
		if err != nil {
			return nil, errors.New("cannot create real profile service")
		}
		if _, err := profiles.Update(ctx, userID, version, "Changed fixture profile", strconv.FormatInt(revision, 10)); err != nil {
			return nil, errors.New("cannot advance owned account revision")
		}
		return map[string]bool{"changed": true}, nil
	case "admin-revoke":
		roles, err := fixtureRoles(input.Role)
		if err != nil || len(roles) == 0 {
			return nil, errors.New("explicit fixture role required for revocation")
		}
		for _, role := range roles {
			if err := rbac.ProvisionRole(ctx, actions, operator, identity, userID, role, true, "test"); err != nil {
				return nil, errors.New("cannot revoke fixture operator grant")
			}
		}
		return map[string]bool{"revoked": true}, nil
	case "admin-state":
		var state struct {
			Status   string `json:"status"`
			Revision string `json:"lifecycle_revision"`
			Version  string `json:"auth_version"`
		}
		if err := pool.QueryRow(ctx, `SELECT status,lifecycle_revision::text,auth_version::text FROM users WHERE id=$1`, userID).Scan(&state.Status, &state.Revision, &state.Version); err != nil {
			return nil, errors.New("cannot inspect fixture account state")
		}
		return state, nil
	case "admin-audit":
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		nc, js, err := natsjs.Connect(ctx, cfg.NATSURL, "portal-fixture", logger)
		if err != nil {
			return nil, errors.New("cannot connect fixture producer to JetStream")
		}
		defer nc.Close()
		ids := make([]uuid.UUID, 0, 8)
		payloadMarker := "portal-admin-audit-private-" + runID
		for index := range 8 {
			event := audit.Event{EventType: audit.EventLoginSucceeded, ActorID: userID, SubjectID: &userID,
				ActorSPIFFEID: identity, ActionStatus: audit.StatusSuccess, ClientIP: "127.0.0.1", UserAgent: "portal-fixture",
				Security: &audit.SecurityContext{AccountRef: userID}}
			id := uuid.New()
			env, err := audit.NewEnvelope(event, id, time.Now().Add(-time.Duration(index+1)*time.Minute))
			if err != nil {
				return nil, errors.New("cannot encode fixture event")
			}
			payload := "<img src=x onerror=globalThis.__adminPayloadExecuted=true> private audit narrative " + payloadMarker
			if input.Scenario == "large-payload" {
				payload += strings.Repeat(" x", 20*1024)
			} else if input.Scenario != "" {
				return nil, errors.New("unsupported audit fixture scenario")
			}
			encoded, err := json.Marshal(map[string]string{"fixture_payload": payload})
			if err != nil {
				return nil, errors.New("cannot encode fixture payload")
			}
			env.Payload = string(encoded)
			body, err := json.Marshal(env)
			if err != nil {
				return nil, errors.New("cannot serialize fixture envelope")
			}
			ack, err := js.Publish(ctx, cfg.Subject, body, jetstream.WithMsgID(id.String()))
			if err != nil || ack == nil || ack.Stream != cfg.StreamName {
				return nil, errors.New("fixture audit publication was not acknowledged")
			}
			ids = append(ids, id)
		}
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			var signed int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log_chain a JOIN security_ledger_chain l USING(event_id) WHERE event_id=ANY($1::uuid[])`, ids).Scan(&signed); err != nil {
				return nil, errors.New("cannot inspect canonical fixture signing")
			}
			if signed == len(ids) {
				return map[string]any{"signed": signed, "canonical_version": audit.EnvelopeSchemaVersion, "event_type": audit.EventLoginSucceeded, "payload_marker": payloadMarker}, nil
			}
			select {
			case <-ctx.Done():
				return nil, errors.New("fixture signing interrupted")
			case <-deadline.C:
				return nil, errors.New("real signer did not persist fixture events")
			case <-ticker.C:
			}
		}
	}
	return nil, errors.New("unsupported administrative fixture operation")
}

func adminWorkerRoles(ctx context.Context, pool *pgxpool.Pool, runID, subject string) (any, error) {
	dsn := os.Getenv("DATABASE_URL")
	if !runIDPattern.MatchString(runID) || validateDatabase(dsn, runID) != nil {
		return nil, errors.New("invalid admin worker database boundary")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, errors.New("cannot begin owned worker provisioning")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	urls := map[string]string{}
	for _, kind := range []string{"signer", "publisher"} {
		password := make([]byte, 32)
		if _, err := rand.Read(password); err != nil {
			return nil, errors.New("cannot generate owned worker credentials")
		}
		secret := base64.RawURLEncoding.EncodeToString(password)
		role := "portal_" + kind + "_" + runID
		identifier := pgx.Identifier{role}.Sanitize()
		statements := []string{
			"CREATE ROLE " + identifier + " LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + secret + "'",
			"GRANT USAGE ON SCHEMA public TO " + identifier,
		}
		if kind == "signer" {
			statements = append(statements,
				"GRANT SELECT, INSERT ON audit_log_chain, security_ledger_chain, mvp_audit_logs, security_event_ledger TO "+identifier,
				"GRANT SELECT ON audit_log_head, security_ledger_head, security_ledger_erasures TO "+identifier,
				"GRANT SELECT ON users TO "+identifier,
				"GRANT UPDATE(id) ON users TO "+identifier,
				"GRANT USAGE ON SEQUENCE audit_log_chain_seq, security_ledger_chain_seq TO "+identifier,
				"GRANT EXECUTE ON FUNCTION advance_chain_head(text,bigint,bigint,bigint,bigint) TO "+identifier,
			)
		} else {
			// Owner API/fixture writes remain unaffected. This real publisher login
			// can see and mark only the configured, committed admin receipt scope.
			predicate := "admin_action AND subject='" + strings.ReplaceAll(subject, "'", "''") + "'"
			statements = append(statements,
				"GRANT SELECT ON event_outbox TO "+identifier,
				"GRANT UPDATE(published_at, attempts, next_attempt_at, last_error) ON event_outbox TO "+identifier,
				"ALTER TABLE event_outbox ENABLE ROW LEVEL SECURITY",
				"CREATE POLICY portal_publisher_read ON event_outbox FOR SELECT TO "+identifier+" USING ("+predicate+")",
				"CREATE POLICY portal_publisher_delivery ON event_outbox FOR UPDATE TO "+identifier+" USING ("+predicate+") WITH CHECK ("+predicate+")",
			)
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return nil, errors.New("cannot install owned worker privileges")
			}
		}
		endpoint, _ := url.Parse(dsn)
		endpoint.User = url.UserPassword(role, secret)
		urls[kind+"_database_url"] = endpoint.String()
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("cannot commit owned worker privileges")
	}
	return urls, nil
}
