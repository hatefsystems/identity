package migrate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func TestV1MigrationRefusalPreservesVersionAndInventory(t *testing.T) {
	for _, version := range []int64{7, 8, 9, 11, 14} {
		for _, inventory := range []string{"audit", "ledger", "head", "checkpoint", "settings"} {
			if version < 11 && inventory != "audit" && inventory != "ledger" {
				continue
			}
			t.Run(fmt.Sprintf("%05d/%s", version, inventory), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
				defer cancel()
				database := openTestDB(ctx, t)
				p, err := NewProvider(database)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.UpTo(ctx, version); err != nil {
					t.Fatal(err)
				}
				var table, insert string
				switch inventory {
				case "audit":
					table = "mvp_audit_logs"
					insert = `INSERT INTO mvp_audit_logs(actor_id,actor_spiffe_id,event_type,action_status,client_ip,user_agent,payload,chain_hash)
						VALUES(gen_random_uuid(),'spiffe://fixture','fixture','success','127.0.0.1','fixture','{}',repeat('a',64))`
				case "ledger":
					table = "security_event_ledger"
					insert = `INSERT INTO security_event_ledger(account_ref,event_type,retain_until,chain_hash)
						VALUES(gen_random_uuid(),'fixture',now(),repeat('b',64))`
				case "head":
					table = "security_ledger_head"
					insert = `INSERT INTO security_ledger_head(singleton,seq,chain_hash) VALUES(true,0,repeat('0',64))`
				case "checkpoint":
					table = "security_ledger_checkpoints"
					insert = `INSERT INTO security_ledger_checkpoints(first_seq,last_seq,predecessor_seq,predecessor_hash,terminal_hash,erased_count)
						VALUES(1,2,0,repeat('0',64),repeat('c',64),2)`
				case "settings":
					table = "security_ledger_retention_settings"
					insert = `INSERT INTO security_ledger_retention_settings(singleton,audit_subject) VALUES(true,'identity.audit.fixture')`
				}
				if _, err := database.ExecContext(ctx, insert); err != nil {
					t.Fatal(err)
				}
				var before, after string
				query := "SELECT jsonb_agg(to_jsonb(t))::text FROM public." + table + " t"
				if err := database.QueryRowContext(ctx, query).Scan(&before); err != nil {
					t.Fatal(err)
				}
				if err := Up(ctx, database); !errors.Is(err, ErrV1History) {
					t.Fatalf("unsafe upgrade: %v", err)
				}
				got, err := p.GetDBVersion(ctx)
				if err != nil || got != version {
					t.Fatalf("version changed: %d, %v", got, err)
				}
				if err := database.QueryRowContext(ctx, query).Scan(&after); err != nil || before != after {
					t.Fatalf("history changed: %v", err)
				}
			})
		}
	}
}

func TestEveryMigrationEntrypointGuards00015(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	database.SetMaxOpenConns(1)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 14); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO security_ledger_head(singleton,seq,chain_hash) VALUES(true,0,repeat('0',64))`); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"Up":           func() error { _, err := p.Up(ctx); return err },
		"UpTo":         func() error { _, err := p.UpTo(ctx, 20); return err },
		"UpByOne":      func() error { _, err := p.UpByOne(ctx); return err },
		"ApplyVersion": func() error { _, err := p.ApplyVersion(ctx, 15, true); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrV1History) {
				t.Fatalf("unguarded entrypoint: %v", err)
			}
			if version, err := p.GetDBVersion(ctx); err != nil || version != 14 {
				t.Fatalf("version %d: %v", version, err)
			}
		})
	}
}

func TestMigrationInventoryFailureAndExclusionCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 14); err != nil {
		t.Fatal(err)
	}
	for _, key := range []int64{pglock.AuditSignerKey, pglock.PurgeKey, pglock.SecurityLedgerPurgeKey, pglock.MigrationKey} {
		conn, err := database.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		err = Up(bounded, database)
		stop()
		if err == nil {
			t.Fatal("migration ignored held exclusion")
		}
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	var locks int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory'
		AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`).Scan(&locks); err != nil || locks != 0 {
		t.Fatalf("cancellation leaked advisory locks: %d, %v", locks, err)
	}
	// All partial acquisitions must have been released on cancellation, including
	// the migration mutex, before trying again with a single pooled connection.
	database.SetMaxOpenConns(1)
	if _, err := database.ExecContext(ctx, "DROP TABLE public.security_ledger_checkpoints"); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, database); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("inventory error did not fail closed: %v", err)
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 14 {
		t.Fatalf("version %d: %v", version, err)
	}
}

func TestWriterAndMigratorRacePreservesNewV1History(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 14); err != nil {
		t.Fatal(err)
	}
	writer, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	if _, err := writer.ExecContext(ctx, "SELECT pg_advisory_lock($1)", pglock.AuditSignerKey); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = writer.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", pglock.AuditSignerKey)
	}()
	done := make(chan error, 1)
	go func() { done <- Up(ctx, database) }()
	observed, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	for {
		var blocked bool
		if err := database.QueryRowContext(observed, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory'
			AND objid=$1 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))`, pglock.MigrationKey).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-observed.Done():
			t.Fatal("migration did not acquire its exclusion")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := writer.ExecContext(ctx, `INSERT INTO mvp_audit_logs(actor_id,actor_spiffe_id,event_type,action_status,client_ip,user_agent,payload,chain_hash)
		VALUES(gen_random_uuid(),'spiffe://fixture','fixture','success','127.0.0.1','fixture','{}',repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", pglock.AuditSignerKey); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrV1History) {
		t.Fatalf("writer/migration race lost history: %v", err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT count(*) FROM mvp_audit_logs").Scan(&count); err != nil || count != 1 {
		t.Fatal("new writer history lost")
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 14 {
		t.Fatalf("version %d: %v", version, err)
	}
}

func TestCompetingMigratorsSerialize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 14); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for range 2 {
		go func() { done <- Up(ctx, database) }()
	}
	for range 2 {
		if err := <-done; err != nil && !strings.Contains(err.Error(), "exclusion") {
			t.Fatalf("competing migration: %v", err)
		}
	}
	if err := Up(ctx, database); err != nil {
		t.Fatalf("bounded contention forward retry: %v", err)
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 20 {
		t.Fatalf("version %d: %v", version, err)
	}
}

func TestVersionTargetedDownRefusalPreservesState(t *testing.T) {
	for version, inventory := range map[int64]struct{ table, insert string }{
		7:  {"users", `INSERT INTO users(email,status) VALUES('banned@fixture.test','banned')`},
		8:  {"event_outbox", `INSERT INTO event_outbox(subject,payload,admin_action) VALUES('identity.audit.fixture','{}',true)`},
		9:  {"legal_holds", `INSERT INTO legal_holds(account_ref,applied_by,details_encrypted) VALUES(gen_random_uuid(),gen_random_uuid(),'\x01')`},
		11: {"security_ledger_head", `INSERT INTO security_ledger_head(singleton,seq,chain_hash) VALUES(true,0,repeat('0',64))`},
		15: {"audit_log_chain", `INSERT INTO audit_log_chain(event_id,leaf_hash,chain_hash) VALUES(gen_random_uuid(),sha256('fixture'),sha256('fixture'))`},
	} {
		t.Run(fmt.Sprintf("%05d", version), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			database := openTestDB(ctx, t)
			p, err := NewProvider(database)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.UpTo(ctx, version); err != nil {
				t.Fatal(err)
			}
			if _, err := database.ExecContext(ctx, inventory.insert); err != nil {
				t.Fatal(err)
			}
			var before, after string
			query := "SELECT jsonb_agg(to_jsonb(t))::text FROM " + inventory.table + " t"
			if err := database.QueryRowContext(ctx, query).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := p.ApplyVersion(ctx, version, false); err == nil {
				t.Fatal("destructive down succeeded")
			}
			if err := database.QueryRowContext(ctx, query).Scan(&after); err != nil || before != after {
				t.Fatal("refused down changed history")
			}
			if got, err := p.GetDBVersion(ctx); err != nil || got != version {
				t.Fatalf("version %d: %v", got, err)
			}
		})
	}
}

func Test00019TerminalAndForwardOnlyBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	database.SetMaxOpenConns(1)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 18); err != nil {
		t.Fatal(err)
	}
	var beforeOwner uint32
	var beforeACL string
	if err := database.QueryRowContext(ctx, `SELECT proowner,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='public.advance_chain_head(text,bigint,bigint,bigint,bigint)'::regprocedure`).Scan(&beforeOwner, &beforeACL); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyVersion(ctx, 19, true); err != nil {
		t.Fatal(err)
	}
	var owner uint32
	var acl, config string
	if err := database.QueryRowContext(ctx, `SELECT proowner,COALESCE(proacl::text,''),proconfig::text FROM pg_proc WHERE oid='public.advance_chain_head(text,bigint,bigint,bigint,bigint)'::regprocedure`).Scan(&owner, &acl, &config); err != nil {
		t.Fatal(err)
	}
	if owner != beforeOwner || acl != beforeACL || !strings.Contains(config, "search_path=pg_catalog, pg_temp") {
		t.Fatal("repair changed owner/ACL/search_path")
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO audit_log_head(singleton,seq,chain_hash) VALUES(true,0,'\x5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb');
		INSERT INTO audit_log_chain(seq,event_id,leaf_hash,chain_hash) VALUES(3,gen_random_uuid(),sha256('leaf'),
		sha256(convert_to('hatef.audit.chain.v2','UTF8') || '\x00'::bytea || '\x5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb'::bytea || sha256('leaf')))`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `SELECT advance_chain_head('audit',0,3,4,1)`); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("phantom terminal accepted: %v", err)
	}
	if _, err := database.ExecContext(ctx, `SELECT advance_chain_head('audit',0,3,3,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyVersion(ctx, 19, false); err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatalf("00019 down: %v", err)
	}
	if _, err := p.ApplyVersion(ctx, 20, true); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyVersion(ctx, 20, false); err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatalf("00020 down: %v", err)
	}
}

func Test00020ContractRefusesIncompleteAndUnexpectedDependency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 19); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO legal_holds(account_ref,applied_by,reason,requesting_authority,legal_basis)
		VALUES(gen_random_uuid(),gen_random_uuid(),'fixture','fixture','fixture')`); err != nil {
		t.Fatal(err)
	}
	var before, after string
	if err := database.QueryRowContext(ctx, `SELECT to_jsonb(h)::text FROM legal_holds h`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyVersion(ctx, 20, true); err == nil {
		t.Fatal("incomplete contraction succeeded")
	}
	if err := database.QueryRowContext(ctx, `SELECT to_jsonb(h)::text FROM legal_holds h`).Scan(&after); err != nil || before != after {
		t.Fatal("failed contraction changed data")
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 19 {
		t.Fatalf("version %d: %v", version, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE legal_holds SET reason=NULL,requesting_authority=NULL,legal_basis=NULL,details_encrypted='\x01'; CREATE VIEW legal_legacy_dependency AS SELECT reason FROM legal_holds`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyVersion(ctx, 20, true); err == nil {
		t.Fatal("unexpected dependency removed")
	}
	if _, err := database.ExecContext(ctx, `DROP VIEW legal_legacy_dependency`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyVersion(ctx, 20, true); err != nil {
		t.Fatal(err)
	}
	var legacy int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid='legal_holds'::regclass AND attname IN ('reason','requesting_authority','legal_basis') AND NOT attisdropped`).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatal("plaintext columns survived")
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO legal_holds(account_ref,applied_by) VALUES(gen_random_uuid(),gen_random_uuid())`); err == nil {
		t.Fatal("unencrypted legacy row accepted after contraction")
	}
}
