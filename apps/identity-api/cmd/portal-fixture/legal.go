//go:build portalfixture

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Deleted subjects cannot be checked against users.email. Deterministic,
// run-specific references keep every later fixture operation owner-scoped.
func legalFixtureReference(runID, kind string) (uuid.UUID, error) {
	if !runIDPattern.MatchString(runID) || (kind != "deleted" && kind != "current" && kind != "absent") {
		return uuid.Nil, errors.New("invalid owned legal reference")
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("portal-legal:"+runID+":"+kind)), nil
}

func ownedLegalReference(runID, raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw {
		return uuid.Nil, errors.New("invalid owned legal subject")
	}
	for _, kind := range []string{"deleted", "current", "absent"} {
		owned, err := legalFixtureReference(runID, kind)
		if err == nil && id == owned {
			return id, nil
		}
	}
	return uuid.Nil, errors.New("legal subject does not belong to this run")
}

func legalFixture(ctx context.Context, pool *pgxpool.Pool, runID, action string, input request) (any, error) {
	cfg, err := fixtureAuditConfig(runID)
	if err != nil {
		return nil, err
	}
	if action == "admin-legal-probe" {
		id, err := uuid.Parse(input.FixtureID)
		if err != nil || id == uuid.Nil || id.String() != input.FixtureID {
			return nil, errors.New("invalid real lookup fixture identifier")
		}
		pepper, err := config.LoadBlindIndexPepper()
		if err != nil {
			return nil, errors.New("missing owned lookup key")
		}
		defer clear(pepper)
		version, err := config.LoadBlindIndexPepperVersion()
		if err != nil {
			return nil, errors.New("invalid owned lookup key version")
		}
		indexer, err := blindindex.New(pepper, version)
		if err != nil || legalhold.VerifyLookupFixture(ctx, pool, indexer, id) != nil {
			return nil, errors.New("real signer fixture did not verify")
		}
		var deleted bool
		if err := pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM users WHERE email=$1)`, legalhold.LookupFixtureEmail(id)).Scan(&deleted); err != nil || !deleted {
			return nil, errors.New("real lookup probe did not finish account deletion")
		}
		pepper[0] ^= 1
		mismatch, err := blindindex.New(pepper, version)
		if err != nil {
			return nil, errors.New("cannot prepare mismatched lookup key")
		}
		return map[string]bool{
			"verified": true, "account_deleted": deleted,
			"missing_rejected":        errors.Is(legalhold.VerifyLookupFixture(ctx, pool, indexer, uuid.Nil), legalhold.ErrUnavailable),
			"wrong_rejected":          errors.Is(legalhold.VerifyLookupFixture(ctx, pool, indexer, uuid.New()), legalhold.ErrUnavailable),
			"mismatched_key_rejected": errors.Is(legalhold.VerifyLookupFixture(ctx, pool, mismatch, id), legalhold.ErrUnavailable),
		}, nil
	}
	if action == "admin-legal-seed" {
		deleted, _ := legalFixtureReference(runID, "deleted")
		current, _ := legalFixtureReference(runID, "current")
		absent, _ := legalFixtureReference(runID, "absent")
		email := "legal-" + runID + "@" + runID + ".example.test"
		// All four rows are genuinely expired under the signer's original clock;
		// browser-created independent holds are the only reason they become eligible.
		occurred := time.Now().UTC().Truncate(time.Second).Add(-cfg.LedgerRetention - 2*time.Hour)
		for _, id := range []uuid.UUID{deleted, current} {
			if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,status) VALUES($1,$2,'active')`, id, email); err != nil {
				return nil, errors.New("cannot create owned legal subject")
			}
			if _, err := publishLegalFixture(ctx, pool, runID, cfg, id, occurred, false); err != nil {
				return nil, err
			}
			if id == deleted {
				result, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1 AND email=$2`, id, email)
				if err != nil || result.RowsAffected() != 1 {
					return nil, errors.New("cannot remove signed owned legal subject")
				}
			} else if _, err := pool.Exec(ctx, `UPDATE users SET status='pending_deletion',deleted_at=now() WHERE id=$1 AND email=$2`, id, email); err != nil {
				return nil, errors.New("cannot prepare soft-deleted legal subject")
			}
		}
		return map[string]any{
			"email": email, "deleted_account_ref": deleted, "current_account_ref": current, "absent_account_ref": absent,
			"start_time": occurred.Add(-time.Minute), "end_time": occurred.Add(time.Hour), "records": 4,
			"metadata": legalFixtureMetadata(runID), "canonical_version": audit.EnvelopeSchemaVersion,
		}, nil
	}
	account, err := ownedLegalReference(runID, input.AccountRef)
	if err != nil {
		return nil, err
	}
	switch action {
	case "admin-legal-append":
		var occurred time.Time
		if err := pool.QueryRow(ctx, `SELECT min(timestamp) FROM security_event_ledger WHERE account_ref=$1 AND client_id=$2`, account, "portal-legal-"+runID).Scan(&occurred); err != nil || occurred.IsZero() {
			return nil, errors.New("append requires an owned signed legal subject")
		}
		return publishLegalFixture(ctx, pool, runID, cfg, account, occurred.Add(time.Minute), true)
	case "admin-legal-state":
		state := struct {
			AccountRef      uuid.UUID `json:"account_ref"`
			Total           int       `json:"total"`
			Active          int       `json:"active"`
			Purged          int       `json:"purged"`
			AccountPresent  bool      `json:"account_present"`
			LedgerPresent   bool      `json:"ledger_evidence_present"`
			EligibleRecords int       `json:"eligible_records"`
			HoldID          string    `json:"hold_id,omitempty"`
			IsActive        bool      `json:"is_active"`
		}{AccountRef: account}
		if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE is_active),count(*) FILTER (WHERE details_purged_at IS NOT NULL),
			EXISTS(SELECT 1 FROM users WHERE id=$1),EXISTS(SELECT 1 FROM security_event_ledger WHERE account_ref=$1),
			(SELECT count(*) FROM security_event_ledger l WHERE l.account_ref=$1 AND (l.retain_until>=now() OR
			EXISTS(SELECT 1 FROM legal_holds h WHERE h.account_ref=$1 AND h.is_active))) FROM legal_holds WHERE account_ref=$1`, account).
			Scan(&state.Total, &state.Active, &state.Purged, &state.AccountPresent, &state.LedgerPresent, &state.EligibleRecords); err != nil {
			return nil, errors.New("cannot inspect owned legal state")
		}
		if input.OperationID != "" {
			key, err := uuid.Parse(input.OperationID)
			if err != nil || key == uuid.Nil || key.String() != input.OperationID ||
				(input.RequestKind != legalhold.KindHold && input.RequestKind != legalhold.KindPreservation) {
				return nil, errors.New("invalid owned legal operation tuple")
			}
			if err := pool.QueryRow(ctx, `SELECT id::text,is_active FROM legal_holds WHERE account_ref=$1 AND request_kind=$2 AND idempotency_key=$3`, account, input.RequestKind, key).
				Scan(&state.HoldID, &state.IsActive); err != nil {
				return nil, errors.New("cannot inspect owned legal operation")
			}
		}
		return state, nil
	case "admin-legal-cleanup":
		enc, err := fixtureEncryptor()
		if err != nil {
			return nil, err
		}
		holds, err := legalhold.New(db.New(pool), enc, legalhold.WithReleasedMetadataRetention(time.Hour))
		if err != nil {
			return nil, errors.New("cannot construct owned legal cleanup")
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, errors.New("cannot lock owned legal cleanup")
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := pglock.LockAccount(ctx, tx, account); err != nil {
			return nil, errors.New("cannot lock owned legal cleanup subject")
		}
		// Only advance this fixture's released-metadata age, never a ledger's
		// signed timestamp/retain_until or a production retention schedule.
		result, err := tx.Exec(ctx, `UPDATE legal_holds SET released_at=now()-interval '2 hours'
			WHERE account_ref=$1 AND NOT is_active AND NOT EXISTS(SELECT 1 FROM legal_holds WHERE account_ref=$1 AND is_active)`, account)
		if err != nil || result.RowsAffected() == 0 {
			return nil, errors.New("owned legal cleanup requires released requests and no active hold")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, errors.New("cannot prepare owned released metadata age")
		}
		count, err := holds.CleanupReleased(ctx, pool, 20)
		if err != nil || count == 0 {
			return nil, errors.New("real legal cleanup did not remove owned narratives")
		}
		return map[string]int64{"cleaned": count}, nil
	default:
		return nil, errors.New("unsupported owned legal scenario")
	}
}

func legalFixtureMetadata(runID string) map[string]string {
	return map[string]string{
		"client_ip": "192.0.2.19", "ip_subnet": "192.0.2.0/24", "client_id": "portal-legal-" + runID,
		"user_agent":         "<img src=x onerror=globalThis.__legalPayloadExecuted=true> legal-private-agent-" + runID,
		"device_fingerprint": "legal-private-device-" + runID, "scope": "legal-private-scope-" + runID,
	}
}

func publishLegalFixture(ctx context.Context, pool *pgxpool.Pool, runID string, cfg config.AuditConfig, account uuid.UUID, occurred time.Time, captured bool) (any, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nc, js, err := natsjs.Connect(ctx, cfg.NATSURL, "portal-legal-fixture", logger)
	if err != nil {
		return nil, errors.New("cannot connect owned legal producer")
	}
	defer nc.Close()
	metadata := legalFixtureMetadata(runID)
	ids := make([]uuid.UUID, 0, 2)
	for range 2 {
		security := &audit.SecurityContext{AccountRef: account, ClientID: metadata["client_id"],
			Scope: metadata["scope"], DeviceFingerprint: metadata["device_fingerprint"]}
		if captured {
			// Later ingestion after deletion uses a supported producer-captured
			// index. Initial rows and the mandatory bootstrap probe never do.
			pepper, err := config.LoadBlindIndexPepper()
			if err != nil {
				return nil, errors.New("cannot load owned producer key")
			}
			version, versionErr := config.LoadBlindIndexPepperVersion()
			indexer, keyErr := blindindex.New(pepper, version)
			clear(pepper)
			if versionErr != nil || keyErr != nil {
				return nil, errors.New("cannot construct owned producer indexer")
			}
			index := indexer.Compute("legal-" + runID + "@" + runID + ".example.test")
			security.IdentityBlindIndex, security.BlindIndexVersion = &index, version
		}
		id := uuid.New()
		event, err := audit.NewEnvelope(audit.Event{EventType: audit.EventLoginSucceeded, ActorID: account, SubjectID: &account,
			ActorSPIFFEID: "spiffe://portal-fixture.test/legal", ActionStatus: audit.StatusSuccess, ClientIP: metadata["client_ip"],
			UserAgent: metadata["user_agent"], Security: security}, id, occurred)
		if err != nil {
			return nil, errors.New("cannot prepare owned legal envelope")
		}
		body, err := json.Marshal(event)
		if err != nil {
			return nil, errors.New("cannot encode owned legal envelope")
		}
		ack, err := js.Publish(ctx, cfg.Subject, body, jetstream.WithMsgID(id.String()))
		if err != nil || ack == nil || ack.Stream != cfg.StreamName {
			return nil, errors.New("owned legal publication was not acknowledged")
		}
		ids = append(ids, id)
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		var through string
		if err := pool.QueryRow(ctx, `SELECT count(*),coalesce(max(l.seq),0)::text FROM security_ledger_chain c
			JOIN security_event_ledger l ON l.seq=c.seq WHERE c.event_id=ANY($1::uuid[]) AND l.account_ref=$2
			AND l.client_id=$3 AND l.identity_blind_index IS NOT NULL`, ids, account, metadata["client_id"]).Scan(&count, &through); err != nil {
			return nil, errors.New("cannot inspect real owned legal signing")
		}
		if count == len(ids) {
			return map[string]any{"signed": count, "through_seq": through, "account_ref": account}, nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("owned legal signing interrupted")
		case <-deadline.C:
			return nil, errors.New("real signer did not index owned legal evidence")
		case <-ticker.C:
		}
	}
}
